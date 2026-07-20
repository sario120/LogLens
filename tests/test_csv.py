import pytest
from app.parsers.csv_parser import CsvParser, _detect_level, COLUMN_MAP


# ── Column mapping ──────────────────────────────────────────────


class TestAutoMapColumns:
    def setup_method(self):
        self.parser = CsvParser()

    def test_timestamp_variants(self):
        for name in ["timestamp", "time", "date", "created_at", "ts", "@timestamp", "datetime"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "timestamp", f"Column '{name}' should map to timestamp"

    def test_level_variants(self):
        for name in ["level", "severity", "log_level", "logtype"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "level", f"Column '{name}' should map to level"

    def test_message_variants(self):
        for name in ["message", "msg", "description", "error", "details"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "message", f"Column '{name}' should map to message"

    def test_ip_variants(self):
        for name in ["ip", "source_ip", "client_ip", "src_ip", "remote_addr"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "ip", f"Column '{name}' should map to ip"

    def test_endpoint_variants(self):
        for name in ["endpoint", "path", "url", "request_uri", "uri"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "endpoint", f"Column '{name}' should map to endpoint"

    def test_method_variants(self):
        for name in ["method", "http_method", "verb"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "method", f"Column '{name}' should map to method"

    def test_status_variants(self):
        for name in ["status", "status_code", "http_code", "response_code"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "status", f"Column '{name}' should map to status"

    def test_duration_variants(self):
        for name in ["duration", "response_time", "rt", "latency", "elapsed"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "duration", f"Column '{name}' should map to duration"

    def test_bytes_variants(self):
        for name in ["bytes", "body_bytes", "size", "bytes_sent"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "bytes", f"Column '{name}' should map to bytes"

    def test_user_variants(self):
        for name in ["user", "username", "user_name"]:
            mapping = self.parser._auto_map_columns([name])
            assert mapping[name] == "user", f"Column '{name}' should map to user"

    def test_unmapped_column(self):
        mapping = self.parser._auto_map_columns(["custom_field", "another"])
        assert mapping["custom_field"] is None
        assert mapping["another"] is None

    def test_mixed_mapped_and_unmapped(self):
        mapping = self.parser._auto_map_columns(["timestamp", "custom", "level", "extra"])
        assert mapping["timestamp"] == "timestamp"
        assert mapping["custom"] is None
        assert mapping["level"] == "level"
        assert mapping["extra"] is None

    def test_duplicate_target_longer_wins(self):
        mapping = self.parser._auto_map_columns(["time", "timestamp", "date"])
        assert mapping["timestamp"] == "timestamp"
        assert mapping["time"] is None
        assert mapping["date"] is None


# ── Level detection ─────────────────────────────────────────────


class TestDetectLevel:
    def test_error(self):
        assert _detect_level("ERROR something broke") == "ERROR"

    def test_fatal(self):
        assert _detect_level("FATAL crash") == "FATAL"

    def test_warning(self):
        assert _detect_level("WARNING low memory") == "WARN"

    def test_info(self):
        assert _detect_level("INFO request processed") == "INFO"

    def test_debug(self):
        assert _detect_level("DEBUG parsing input") == "DEBUG"

    def test_unknown(self):
        assert _detect_level("just some text") == "UNKNOWN"

    def test_empty(self):
        assert _detect_level("") == "UNKNOWN"

    def test_none_like(self):
        assert _detect_level(None) == "UNKNOWN"


# ── CSV parsing ─────────────────────────────────────────────────


BASIC_CSV = "timestamp,level,message\n2025-07-18 10:00:00,INFO,Started\n2025-07-18 10:01:00,ERROR,Failed\n2025-07-18 10:02:00,INFO,Done"


class TestParseCSV:
    def test_basic_parse(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert report["log_type"] == "csv"
        assert report["parsed"] == 3
        assert report["total_lines"] == 4  # header + 3 data + possible trailing

    def test_entries_have_mapped_keys(self):
        parser = CsvParser()
        parser.parse(BASIC_CSV)
        entry = parser.entries[0]
        assert "timestamp" in entry
        assert "level" in entry
        assert "message" in entry

    def test_empty_input(self):
        parser = CsvParser()
        report = parser.parse("")
        assert report["parsed"] == 0
        assert report["total_lines"] == 0

    def test_header_only(self):
        parser = CsvParser()
        report = parser.parse("col1,col2,col3")
        assert report["parsed"] == 0
        assert report["parse_errors"] == 0

    def test_single_column_rejected(self):
        parser = CsvParser()
        report = parser.parse("only_one_column\nvalue1\nvalue2")
        assert report["parsed"] == 0

    def test_quoted_fields(self):
        raw = 'timestamp,message\n2025-07-18,"hello, world"\n2025-07-19,"foo ""bar"" baz"'
        parser = CsvParser()
        report = parser.parse(raw)
        assert report["parsed"] == 2
        assert parser.entries[0]["message"] == "hello, world"
        assert parser.entries[1]["message"] == 'foo "bar" baz'

    def test_empty_lines_skipped(self):
        raw = "a,b,c\n1,2,3\n\n4,5,6\n"
        parser = CsvParser()
        report = parser.parse(raw)
        assert report["parsed"] == 2

    def test_short_row_parsed_with_none_values(self):
        raw = "a,b,c\n1,2,3\n4\n7,8,9"
        parser = CsvParser()
        report = parser.parse(raw)
        assert report["parsed"] == 3
        assert parser.entries[1]["a"] == "4"
        assert parser.entries[1]["b"] is None

    def test_all_none_values_rejected(self):
        raw = "a,b,c\n,,\n1,2,3"
        parser = CsvParser()
        report = parser.parse(raw)
        assert report["parsed"] == 1

    def test_raw_lines_stored(self):
        parser = CsvParser()
        parser.parse(BASIC_CSV)
        assert len(parser._raw_lines) > 0
        assert parser._raw_lines[0].startswith("timestamp")


# ── Report structure ────────────────────────────────────────────


class TestReportStructure:
    def test_summary_keys(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert report["summary"]["total_entries"] == 3
        assert "columns" in report["summary"]
        assert "all_columns" in report["summary"]
        assert "timestamp" in report["summary"]["columns"]
        assert "level" in report["summary"]["columns"]

    def test_time_range(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert report["time_range"]["start"] is not None
        assert report["time_range"]["end"] is not None

    def test_entries_in_report(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert "_entries" in report
        assert len(report["_entries"]) == 3

    def test_log_type_label(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert report["log_type_label"] == "CSV Log"

    def test_processing_ms(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert report["processing_ms"] >= 0


# ── Charts ──────────────────────────────────────────────────────


class TestCharts:
    def test_hourly_timeline(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert "hourly_timeline" in report["charts"]
        timeline = report["charts"]["hourly_timeline"]
        assert len(timeline) > 0
        assert "label" in timeline[0]
        assert "value" in timeline[0]

    def test_level_distribution(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        dist = report["charts"]["level_distribution"]
        labels = [d["label"] for d in dist]
        assert "INFO" in labels
        assert "ERROR" in labels

    def test_status_distribution(self):
        raw = "status,message\n200,OK\n404,Not Found\n200,OK\n500,Error"
        parser = CsvParser()
        report = parser.parse(raw)
        dist = report["charts"]["status_distribution"]
        labels = [d["label"] for d in dist]
        assert "200" in labels

    def test_method_distribution(self):
        raw = "method,path\nGET,/api\nPOST,/api\nGET,/health"
        parser = CsvParser()
        report = parser.parse(raw)
        dist = report["charts"]["method_distribution"]
        labels = [d["label"] for d in dist]
        assert "GET" in labels
        assert "POST" in labels

    def test_duration_histogram(self):
        raw = "duration,message\n100,fast\n200,med\n300,slow\n400,slower\n500,slowest\n150,ok\n250,meh\n350,ugh\n450,nope\n550,yikes\n600,very slow"
        parser = CsvParser()
        report = parser.parse(raw)
        hist = report["charts"]["duration_histogram"]
        assert len(hist) == 10
        assert sum(h["value"] for h in hist) == 11

    def test_top_ips(self):
        raw = "ip,message\n1.2.3.4,req1\n1.2.3.4,req2\n5.6.7.8,req3"
        parser = CsvParser()
        report = parser.parse(raw)
        ips = report["charts"]["top_ips"]
        assert ips[0]["label"] == "1.2.3.4"
        assert ips[0]["value"] == 2

    def test_top_endpoints(self):
        raw = "endpoint,count\n/api/v1,10\n/api/v2,5\n/api/v1,3"
        parser = CsvParser()
        report = parser.parse(raw)
        eps = report["charts"]["top_endpoints"]
        assert eps[0]["label"] == "/api/v1"

    def test_no_level_column_no_level_chart(self):
        raw = "timestamp,message\n2025-07-18,hello\n2025-07-19,world"
        parser = CsvParser()
        report = parser.parse(raw)
        assert "level_distribution" not in report["charts"]

    def test_no_timestamp_no_hourly(self):
        raw = "level,message\nINFO,hello\nERROR,world"
        parser = CsvParser()
        report = parser.parse(raw)
        assert "hourly_timeline" not in report["charts"]

    def test_no_duration_no_histogram(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert "duration_histogram" not in report["charts"]


# ── Tables ──────────────────────────────────────────────────────


class TestTables:
    def test_level_summary(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        levels = report["tables"]["levels"]
        assert len(levels) == 2
        info = [l for l in levels if l["level"] == "INFO"][0]
        assert info["count"] == 2
        assert info["pct"] > 0

    def test_status_summary(self):
        raw = "status,message\n200,OK\n404,Not Found\n200,OK"
        parser = CsvParser()
        report = parser.parse(raw)
        statuses = report["tables"]["status_codes"]
        assert len(statuses) == 2

    def test_ip_summary(self):
        raw = "ip,message\n10.0.0.1,a\n10.0.0.1,b\n10.0.0.2,c"
        parser = CsvParser()
        report = parser.parse(raw)
        details = report["tables"]["ip_details"]
        assert details[0]["ip"] == "10.0.0.1"
        assert details[0]["total"] == 2
        assert details[0]["error_count"] == 0

    def test_endpoint_summary(self):
        raw = "endpoint,msg\n/api,a\n/health,b\n/api,c\n/api,d"
        parser = CsvParser()
        report = parser.parse(raw)
        details = report["tables"]["endpoint_details"]
        assert details[0]["endpoint"] == "/api"
        assert details[0]["total"] == 3

    def test_error_samples(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        samples = report["tables"]["error_samples"]
        assert len(samples) == 1
        assert samples[0]["level"] == "ERROR"
        assert "_entry_idx" in samples[0]

    def test_all_rows_present(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert "all_rows" in report["tables"]
        assert len(report["tables"]["all_rows"]) == 3

    def test_all_rows_no_cap(self):
        lines = ["a,b"] + [f"{i},{i}" for i in range(600)]
        raw = "\n".join(lines)
        parser = CsvParser()
        report = parser.parse(raw)
        assert len(report["tables"]["all_rows"]) == 600

    def test_all_rows_original_columns(self):
        raw = "custom_a,custom_b,custom_c\n1,2,3\n4,5,6"
        parser = CsvParser()
        report = parser.parse(raw)
        row = report["tables"]["all_rows"][0]
        assert "custom_a" in row
        assert "custom_b" in row
        assert "custom_c" in row


# ── Summary metrics ─────────────────────────────────────────────


class TestSummaryMetrics:
    def test_error_rate(self):
        parser = CsvParser()
        report = parser.parse(BASIC_CSV)
        assert report["summary"]["error_count"] == 1
        assert report["summary"]["error_rate"] == pytest.approx(33.33, abs=0.01)

    def test_duration_stats(self):
        raw = "duration,msg\n100,a\n200,b\n300,c\n400,d\n500,e"
        parser = CsvParser()
        report = parser.parse(raw)
        s = report["summary"]
        assert s["avg_duration"] == 300.0
        assert s["min_duration"] == 100.0
        assert s["max_duration"] == 500.0
        assert s["p95_duration"] == 500.0

    def test_unique_ips(self):
        raw = "ip,msg\n1.2.3.4,a\n1.2.3.4,b\n5.6.7.8,c"
        parser = CsvParser()
        report = parser.parse(raw)
        assert report["summary"]["unique_ips"] == 2

    def test_unique_endpoints(self):
        raw = "endpoint,count\n/api,1\n/health,2\n/api,3"
        parser = CsvParser()
        report = parser.parse(raw)
        assert report["summary"]["unique_endpoints"] == 2

    def test_total_bytes(self):
        raw = "bytes,msg\n1024,a\n2048,b\n512,c"
        parser = CsvParser()
        report = parser.parse(raw)
        assert report["summary"]["total_bytes"] == 3584
        assert "total_bytes_human" in report["summary"]

    def test_no_error_when_no_level(self):
        raw = "timestamp,message\n2025-07-18,hello"
        parser = CsvParser()
        report = parser.parse(raw)
        assert "error_count" not in report["summary"]
        assert "error_rate" not in report["summary"]


# ── IP exclusion ────────────────────────────────────────────────


class TestExcludeIPs:
    def test_exclude_basic(self):
        raw = "ip,level,msg\n10.0.0.1,INFO,a\n10.0.0.2,ERROR,b\n10.0.0.1,WARN,c"
        parser = CsvParser()
        report = parser.parse(raw, exclude_ips=["10.0.0.1"])
        assert report["parsed"] == 1
        assert parser.entries[0]["ip"] == "10.0.0.2"

    def test_exclude_none_matching(self):
        raw = "ip,msg\n10.0.0.1,a\n10.0.0.2,b"
        parser = CsvParser()
        report = parser.parse(raw, exclude_ips=["192.168.1.1"])
        assert report["parsed"] == 2

    def test_exclude_all(self):
        raw = "ip,msg\n10.0.0.1,a\n10.0.0.1,b"
        parser = CsvParser()
        report = parser.parse(raw, exclude_ips=["10.0.0.1"])
        assert report["parsed"] == 0

    def test_exclude_with_source_ip_key(self):
        raw = "source_ip,level,msg\n10.0.0.1,INFO,a\n10.0.0.2,ERROR,b"
        parser = CsvParser()
        report = parser.parse(raw, exclude_ips=["10.0.0.1"])
        assert report["parsed"] == 1

    def test_exclude_with_client_key(self):
        raw = "client,level,msg\n10.0.0.1,INFO,a\n10.0.0.2,ERROR,b"
        parser = CsvParser()
        report = parser.parse(raw, exclude_ips=["10.0.0.1"])
        assert report["parsed"] == 1


# ── Context ─────────────────────────────────────────────────────


class TestContext:
    def test_get_context(self):
        parser = CsvParser()
        parser.parse(BASIC_CSV)
        ctx = parser.get_context(0)
        assert "context" in ctx
        assert len(ctx["context"]) > 0

    def test_get_context_invalid(self):
        parser = CsvParser()
        parser.parse(BASIC_CSV)
        ctx = parser.get_context(999)
        assert "error" in ctx


# ── Human bytes ─────────────────────────────────────────────────


class TestHumanBytes:
    def test_bytes(self):
        assert CsvParser._human_bytes(500) == "500.0 B"

    def test_kb(self):
        assert CsvParser._human_bytes(1536) == "1.5 KB"

    def test_mb(self):
        assert CsvParser._human_bytes(1048576) == "1.0 MB"

    def test_gb(self):
        assert CsvParser._human_bytes(1073741824) == "1.0 GB"
