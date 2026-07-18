from app.parsers.postgres import PostgresParser, _normalize_query, _build_duration_histogram

PG_LOG = '2025-07-18 14:30:00.123 UTC [1234] LOG:  database system is ready to accept connections'
PG_STATEMENT = '2025-07-18 14:30:01.456 UTC [1234] LOG:  duration: 150.500 ms  statement: SELECT * FROM users WHERE id = 42'
PG_DURATION_ONLY = '2025-07-18 14:30:02.789 UTC [1234] LOG:  duration: 25.000 ms'
PG_ERROR = '2025-07-18 14:30:03.012 UTC [1234] ERROR:  relation "users" does not exist'
PG_WARNING = '2025-07-18 14:30:04.345 UTC [1234] WARNING:  cache reference leak'
PG_CHECKPOINT = '2025-07-18 14:30:05.678 UTC [1234] LOG:  checkpoint starting: time'
PG_CHECKPOINT_COMPLETE = '2025-07-18 14:30:06.901 UTC [1234] LOG:  checkpoint complete: wrote 1000 buffers (1.2%); total=5.234 s write=3.100 s sync=1.500 s wait=0.634 s'
PG_LOCK = '2025-07-18 14:30:07.234 UTC [1234] ERROR:  deadlock detected'
PG_AUTOVACUUM = '2025-07-18 14:30:08.567 UTC [1234] LOG:  autovacuum: for table "public.orders": 500 dead tuples, 1000 live tuples'
PG_REPLICATION = '2025-07-18 14:30:09.890 UTC [1234] LOG:  replication lag = 2.5 s'
PG_LISTEN = '2025-07-18 14:30:10.123 UTC [1234] LOG:  listening on IPv4 address "0.0.0.0", port 5432'
PG_RECOVERY = '2025-07-18 14:30:11.456 UTC [1234] LOG:  database system was shut down in recovery mode'
PG_NON_STANDARD = 'PostgreSQL 16.3 started'


def test_normalize_query_string_literals():
    result = _normalize_query("SELECT * FROM users WHERE name = 'john'")
    assert "'?'" in result
    assert "'john'" not in result


def test_normalize_query_numeric_literals():
    result = _normalize_query("SELECT * FROM users WHERE id = 42")
    assert "42" not in result


def test_normalize_query_in_list():
    result = _normalize_query("SELECT * FROM t WHERE id IN (1, 2, 3)")
    assert "IN (?)" in result


def test_normalize_query_consecutive():
    result = _normalize_query("SELECT ?, ?, ?, ?")
    assert result.count("?") < 4


def test_build_duration_histogram_empty():
    assert _build_duration_histogram([]) == []


def test_build_duration_histogram_values():
    durations = [0.5, 5.0, 25.0, 75.0, 250.0, 750.0, 2000.0, 10000.0]
    result = _build_duration_histogram(durations)
    assert len(result) >= 5
    labels = [b["label"] for b in result]
    assert "< 1ms" in labels
    assert "> 5s" in labels


def test_parse_line_startup():
    parser = PostgresParser()
    entry = parser._parse_line(PG_NON_STANDARD)
    assert entry is not None
    assert entry["event"] == "startup"
    assert entry["level"] == "INFO"


def test_parse_line_statement():
    parser = PostgresParser()
    entry = parser._parse_line(PG_STATEMENT)
    assert entry is not None
    assert entry["event"] == "statement"
    assert entry["duration_ms"] == 150.5
    assert entry["stmt_type"] == "SELECT"
    assert entry["table"] == "users"
    assert entry["normalized"] is not None


def test_parse_line_duration_only():
    parser = PostgresParser()
    entry = parser._parse_line(PG_DURATION_ONLY)
    assert entry is not None
    assert entry["event"] == "duration"
    assert entry["duration_ms"] == 25.0


def test_parse_line_statement_only():
    log = '2025-07-18 14:30:01.000 UTC [1234] LOG:  statement: INSERT INTO logs VALUES (1, 2)'
    parser = PostgresParser()
    entry = parser._parse_line(log)
    assert entry is not None
    assert entry["event"] == "statement"
    assert entry["stmt_type"] == "INSERT"


def test_parse_line_error():
    parser = PostgresParser()
    entry = parser._parse_line(PG_ERROR)
    assert entry is not None
    assert entry["event"] == "error"
    assert entry["level"] == "ERROR"


def test_parse_line_warning():
    parser = PostgresParser()
    entry = parser._parse_line(PG_WARNING)
    assert entry is not None
    assert entry["event"] == "warning"
    assert entry["level"] == "WARNING"


def test_parse_line_checkpoint():
    parser = PostgresParser()
    entry = parser._parse_line(PG_CHECKPOINT)
    assert entry is not None
    assert entry["event"] == "checkpoint"


def test_parse_line_lock():
    parser = PostgresParser()
    entry = parser._parse_line(PG_LOCK)
    assert entry is not None
    assert entry["event"] == "lock"
    assert len(parser._lock_events) == 1


def test_parse_line_autovacuum():
    parser = PostgresParser()
    entry = parser._parse_line(PG_AUTOVACUUM)
    assert entry is not None
    assert entry["event"] == "autovacuum"
    assert len(parser._autovacuum_events) == 1
    assert parser._autovacuum_events[0]["table"] == "public.orders"


def test_parse_line_autovacuum_tuple_counts():
    parser = PostgresParser()
    parser._parse_line(PG_AUTOVACUUM)
    av = parser._autovacuum_events[0]
    assert av["dead_tuples"] == 500
    assert av["live_tuples"] == 1000


def test_parse_line_replication():
    parser = PostgresParser()
    entry = parser._parse_line(PG_REPLICATION)
    assert entry is not None
    assert entry["event"] == "replication"
    assert len(parser._replication_events) == 1
    assert parser._replication_events[0]["lag_value"] == "2.5"
    assert parser._replication_events[0]["lag_unit"] == "s"


def test_parse_line_listen():
    parser = PostgresParser()
    entry = parser._parse_line(PG_LISTEN)
    assert entry is not None
    assert entry["event"] == "listen"


def test_parse_line_recovery():
    parser = PostgresParser()
    entry = parser._parse_line(PG_RECOVERY)
    assert entry is not None
    assert entry["event"] == "recovery"


def test_parse_line_ready():
    parser = PostgresParser()
    entry = parser._parse_line(PG_LOG)
    assert entry is not None
    assert entry["event"] == "ready"


def test_parse_line_invalid():
    parser = PostgresParser()
    assert parser._parse_line("not a pg log") is None


def test_parse_line_slow_query():
    log = '2025-07-18 14:30:01.000 UTC [1234] LOG:  duration: 20000.000 ms  statement: SELECT * FROM big_table'
    parser = PostgresParser()
    entry = parser._parse_line(log)
    assert entry["slow"] is True


def test_parse_line_not_slow():
    parser = PostgresParser()
    entry = parser._parse_line(PG_STATEMENT)
    assert entry["slow"] is False


def test_hour_key_override():
    parser = PostgresParser()
    assert parser._hour_key("2025-07-18T14:30:00") == "2025-07-18 14:00"
    assert parser._hour_key("") == "unknown"
    assert parser._hour_key("2025-07-18 14:30") == "2025-07-18 14:00"


def test_full_report_basic():
    raw = PG_LOG + "\n" + PG_STATEMENT + "\n" + PG_ERROR
    parser = PostgresParser()
    report = parser.parse(raw)
    assert report["log_type"] == "postgres"
    assert report["parsed"] == 3
    assert report["summary"]["statements"] == 1
    assert report["summary"]["errors"] == 1


def test_full_report_checkpoint_metrics():
    parser = PostgresParser()
    report = parser.parse(PG_CHECKPOINT_COMPLETE)
    assert report["checkpoint_metrics"] is not None
    assert report["checkpoint_metrics"]["count"] == 1
    assert report["checkpoint_metrics"]["total_avg"] == 5.234


def test_full_report_duration_stats():
    parser = PostgresParser()
    report = parser.parse(PG_STATEMENT)
    assert report["duration_stats"] is not None
    assert report["duration_stats"]["count"] == 1


def test_full_report_slow_queries():
    log_slow = '2025-07-18 14:30:01.000 UTC [1234] LOG:  duration: 50000.000 ms  statement: SELECT * FROM huge_table'
    parser = PostgresParser()
    report = parser.parse(log_slow)
    assert len(report["slow_queries"]) == 1


def test_full_report_normalized_queries():
    parser = PostgresParser()
    report = parser.parse(PG_STATEMENT)
    assert len(report["normalized_queries"]) >= 1
    assert report["normalized_queries"][0]["count"] == 1


def test_full_report_lock_analysis():
    parser = PostgresParser()
    report = parser.parse(PG_LOCK)
    assert report["lock_summary"]["total"] == 1
    assert "deadlock" in report["lock_summary"]["by_type"]


def test_full_report_autovacuum_analysis():
    parser = PostgresParser()
    report = parser.parse(PG_AUTOVACUUM)
    assert report["autovacuum_summary"]["total"] == 1
    assert "public.orders" in report["autovacuum_summary"]["by_table"]


def test_full_report_replication_analysis():
    parser = PostgresParser()
    report = parser.parse(PG_REPLICATION)
    assert report["replication_summary"]["total"] == 1
    assert report["replication_summary"]["lag_stats"]["avg"] == 2.5


def test_full_report_lock_type_classification():
    timeout_log = '2025-07-18 14:30:07.000 UTC [1234] ERROR:  lock timeout'
    wait_log = '2025-07-18 14:30:08.000 UTC [1234] LOG:  waiting for Lock'
    raw = timeout_log + "\n" + wait_log
    parser = PostgresParser()
    report = parser.parse(raw)
    by_type = report["lock_summary"]["by_type"]
    assert "timeout" in by_type
    assert "wait" in by_type


def test_full_report_read_write_tx_counts():
    raw = (
        PG_STATEMENT + "\n" +
        '2025-07-18 14:30:02.000 UTC [1234] LOG:  statement: INSERT INTO logs VALUES (1, 2)\n' +
        '2025-07-18 14:30:03.000 UTC [1234] LOG:  statement: BEGIN\n' +
        '2025-07-18 14:30:04.000 UTC [1234] LOG:  statement: COMMIT'
    )
    parser = PostgresParser()
    report = parser.parse(raw)
    assert report["summary"]["read_queries"] >= 1
    assert report["summary"]["write_queries"] >= 1
    assert report["summary"]["tx_ops"] >= 2


def test_full_report_charts():
    raw = PG_STATEMENT + "\n" + PG_ERROR + "\n" + PG_WARNING
    parser = PostgresParser()
    report = parser.parse(raw)
    assert "level_distribution" in report["charts"]
    assert "top_tables" in report["charts"]
    assert "top_errors" in report["charts"]
    assert "top_warnings" in report["charts"]


def test_error_samples():
    parser = PostgresParser()
    report = parser.parse(PG_ERROR)
    assert len(report["tables"]["error_samples"]) == 1
    assert "_entry_idx" in report["tables"]["error_samples"][0]


def test_warning_samples():
    parser = PostgresParser()
    report = parser.parse(PG_WARNING)
    assert len(report["tables"]["warning_samples"]) == 1


def test_statement_types_table():
    raw = PG_STATEMENT + "\n" + '2025-07-18 14:30:02.000 UTC [1234] LOG:  statement: INSERT INTO logs VALUES (1, 2)'
    parser = PostgresParser()
    report = parser.parse(raw)
    assert len(report["tables"]["statement_types"]) >= 2


def test_top_tables():
    parser = PostgresParser()
    report = parser.parse(PG_STATEMENT)
    assert len(report["tables"]["top_tables"]) == 1
    assert report["tables"]["top_tables"][0]["table"] == "users"


def test_duration_histogram_chart():
    parser = PostgresParser()
    report = parser.parse(PG_STATEMENT)
    assert report["charts"]["duration_histogram"] is not None


def test_top_tables_by_duration():
    parser = PostgresParser()
    report = parser.parse(PG_STATEMENT)
    assert len(report["charts"]["top_tables_by_duration"]) == 1


def test_replication_no_lag():
    no_lag = '2025-07-18 14:30:09.000 UTC [1234] LOG:  wal sender connected'
    parser = PostgresParser()
    report = parser.parse(no_lag)
    assert report["replication_summary"]["lag_stats"] is None


def test_lock_other_type():
    other_lock = '2025-07-18 14:30:07.000 UTC [1234] ERROR:  could not serialize lock'
    parser = PostgresParser()
    report = parser.parse(other_lock)
    assert "other" in report["lock_summary"]["by_type"]


def test_duration_histogram_all_buckets():
    durations = [0.1, 5.0, 25.0, 75.0, 250.0, 750.0, 3000.0, 10000.0]
    result = _build_duration_histogram(durations)
    assert len(result) == 8


def test_statement_type_delete():
    log = '2025-07-18 14:30:02.000 UTC [1234] LOG:  statement: DELETE FROM users WHERE id = 1'
    parser = PostgresParser()
    entry = parser._parse_line(log)
    assert entry["stmt_type"] == "DELETE"


def test_statement_type_update():
    log = '2025-07-18 14:30:02.000 UTC [1234] LOG:  statement: UPDATE users SET name = "x" WHERE id = 1'
    parser = PostgresParser()
    entry = parser._parse_line(log)
    assert entry["stmt_type"] == "UPDATE"


def test_statement_type_other():
    log = '2025-07-18 14:30:02.000 UTC [1234] LOG:  statement: GRANT ALL ON users TO admin'
    parser = PostgresParser()
    entry = parser._parse_line(log)
    assert entry["stmt_type"] == "OTHER"


def test_message_truncation():
    long_msg = 'A' * 600
    log = f'2025-07-18 14:30:01.000 UTC [1234] LOG:  {long_msg}'
    parser = PostgresParser()
    entry = parser._parse_line(log)
    assert len(entry["message"]) == 500


def test_hourly_stmts_and_errors():
    raw = PG_STATEMENT + "\n" + PG_ERROR
    parser = PostgresParser()
    report = parser.parse(raw)
    assert len(report["charts"]["hourly_stmts"]) >= 1
    assert len(report["charts"]["hourly_errors"]) >= 1


def test_unique_pids():
    raw = '2025-07-18 14:30:01.000 UTC [111] LOG:  statement: SELECT 1\n2025-07-18 14:30:02.000 UTC [222] LOG:  statement: SELECT 2'
    parser = PostgresParser()
    report = parser.parse(raw)
    assert report["summary"]["unique_pids"] == 2


def test_unique_tables():
    raw = PG_STATEMENT + "\n2025-07-18 14:30:02.000 UTC [1234] LOG:  duration: 10.000 ms  statement: SELECT * FROM orders WHERE id = 1"
    parser = PostgresParser()
    report = parser.parse(raw)
    assert report["summary"]["unique_tables"] == 2
