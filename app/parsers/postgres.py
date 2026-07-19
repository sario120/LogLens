import re
from collections import Counter, defaultdict
from app.parsers.base import BaseParser
from app.config import SLOW_THRESHOLD

PG_LINE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)'
    r'\s+(?P<tz>\S+)'
    r'\s+\[(?P<pid>\d+)\]'
    r'\s+(?P<level>LOG|WARNING|ERROR|FATAL|PANIC|DEBUG|INFO|NOTICE|DETAIL|HINT|STATEMENT|CONTEXT)'
    r'\s*:\s+'
    r'(?P<message>.+)'
)

NON_PG_LINE = re.compile(r'^(?:PostgreSQL\s|LOG:\s)')

STMT_TYPE = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|BEGIN|COMMIT|ROLLBACK|SET|CREATE|ALTER|DROP|TRUNCATE|COPY)\b',
    re.I,
)

TABLE_EXTRACT = re.compile(
    r'(?:FROM|INTO|UPDATE|JOIN)\s+"?([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?)"?',
    re.I,
)

CKPT_TOTAL = re.compile(r'total=(\d+\.\d+)\s*s')
CKPT_WRITE = re.compile(r'write=(\d+\.\d+)\s*s')
CKPT_SYNC = re.compile(r'sync=(\d+\.\d+)\s*s')
CKPT_BUFFERS = re.compile(r'wrote\s+(\d+)\s+buffers')

DURATION_EXTRACT = re.compile(r'duration:\s*([\d.]+)\s*ms')

SLOW_QUERY_MS = SLOW_THRESHOLD * 1000.0

# --- Advanced PG patterns ---
LOCK_PATTERN = re.compile(
    r'(?:deadlock detected|lock (?:timeout|wait)|waiting for (?:Lock|relation)|'
    r'lock .* on (?:relation|tuple)|process \d+ conflicts with process \d+|'
    r'could not (?:serialize|obtain) lock)',
    re.I,
)

AUTOVACUUM_PATTERN = re.compile(
    r'autovacuum(?:\s+launcher)?(?:\s+worker)?(?:\s+\d+)?:?\s+(?:'
    r'for table\s+"?(?P<table>\S+?)"?\s*:?\s*(?P<av_info>.+)?|'
    r'(?:Launching|started|completed|removed)\s+.+)',
    re.I,
)

AUTOVACUUM_TABLE = re.compile(
    r'autovacuum(?:\s+launcher)?(?:\s+worker)?(?:\s+\d+)?:?\s+for table\s+"?(?P<table>[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?)"?\s*:?\s*(?P<info>.*)',
    re.I,
)

REPLICATION_PATTERN = re.compile(
    r'(?:replication (?:slot|origin|lag|timeout|checkpoint)|'
    r'wal (?:sender|receiver|segment|archive|level)|'
    r'standby (?:mode|connected|sync)|'
    r'remote (?:write|flush|apply|replay))',
    re.I,
)

REPLICATION_LAG_VALUE = re.compile(
    r'(?:replication lag|lag)\s*[=:]\s*(?P<value>[\d.]+)\s*(?P<unit>ms|s|min|m|h|bytes|kB|MB|GB)?',
    re.I,
)

PG_LOCK_PATTERN = re.compile(
    r'(?:Lock|lock)\s+(?:type|mode)?\s*[=:]\s*(\S+)',
    re.I,
)

DEAD_TUPLES_PATTERN = re.compile(
    r'(\d+)\s+dead\s+tuples',
    re.I,
)

LIVE_TUPLES_PATTERN = re.compile(
    r'(\d+)\s+live\s+tuples',
    re.I,
)


def _normalize_query(stmt: str) -> str:
    """Replace literals in SQL with ? placeholders for grouping."""
    s = stmt.strip()
    # String literals
    s = re.sub(r"'[^']*'", "'?'", s)
    # Numeric literals
    s = re.sub(r'\b\d+\.?\d*\b', '?', s)
    # IN lists: IN (?,?,?,...) → IN (?)
    s = re.sub(r'IN\s*\(\?(?:,\s*\?)*\)', 'IN (?)', s, flags=re.I)
    # Multiple consecutive ? from collapsed values
    s = re.sub(r'(\?\s*,\s*){2,}', '?, ', s)
    return s.strip()


class PostgresParser(BaseParser):
    name = "postgres"
    description = "PostgreSQL logs (stderr format with timestamps)"

    def __init__(self):
        super().__init__()
        self._lock_events = []
        self._autovacuum_events = []
        self._replication_events = []
        self._normalized_queries = Counter()

    def _parse_line(self, line: str) -> dict | None:
        if NON_PG_LINE.match(line):
            return {
                "timestamp": "",
                "pid": 0,
                "level": "INFO",
                "event": "startup",
                "message": line.strip(),
                "table": None,
                "stmt_type": None,
                "duration_ms": None,
                "slow": False,
                "normalized": None,
            }

        m = PG_LINE.match(line)
        if not m:
            return None

        d = m.groupdict()
        message = d["message"].strip()
        level = d["level"]

        event = "other"
        table = None
        stmt_type = None
        duration_ms = None
        normalized = None

        dm = DURATION_EXTRACT.search(message)
        if dm:
            duration_ms = float(dm.group(1))
            stmt_match = re.search(r'statement:\s*(.+)', message)
            if stmt_match:
                raw_stmt = stmt_match.group(1).strip()
                sm = STMT_TYPE.search(raw_stmt)
                stmt_type = sm.group(1).upper() if sm else "OTHER"
                table_m = TABLE_EXTRACT.search(raw_stmt)
                table = table_m.group(1) if table_m else None
                normalized = _normalize_query(raw_stmt)
                event = "statement"
            else:
                event = "duration"
        elif message.startswith("statement:"):
            raw_stmt = message[len("statement:"):].strip()
            sm = STMT_TYPE.search(raw_stmt)
            stmt_type = sm.group(1).upper() if sm else "OTHER"
            table_m = TABLE_EXTRACT.search(raw_stmt)
            table = table_m.group(1) if table_m else None
            normalized = _normalize_query(raw_stmt)
            event = "statement"
        elif LOCK_PATTERN.search(message):
            event = "lock"
            self._lock_events.append({
                "timestamp": d["timestamp"].replace(" ", "T", 1),
                "pid": int(d["pid"]),
                "level": level,
                "message": message[:300],
            })
        elif AUTOVACUUM_TABLE.search(message):
            event = "autovacuum"
            av_m = AUTOVACUUM_TABLE.search(message)
            av_table = av_m.group("table") if av_m else None
            av_info = av_m.group("info") if av_m else ""
            dead_match = DEAD_TUPLES_PATTERN.search(av_info) if av_info else None
            live_match = LIVE_TUPLES_PATTERN.search(av_info) if av_info else None
            self._autovacuum_events.append({
                "timestamp": d["timestamp"].replace(" ", "T", 1),
                "pid": int(d["pid"]),
                "table": av_table,
                "dead_tuples": int(dead_match.group(1)) if dead_match else None,
                "live_tuples": int(live_match.group(1)) if live_match else None,
                "message": message[:300],
            })
        elif REPLICATION_PATTERN.search(message):
            event = "replication"
            lag_m = REPLICATION_LAG_VALUE.search(message)
            self._replication_events.append({
                "timestamp": d["timestamp"].replace(" ", "T", 1),
                "pid": int(d["pid"]),
                "level": level,
                "message": message[:300],
                "lag_value": lag_m.group("value") if lag_m else None,
                "lag_unit": lag_m.group("unit") if lag_m else None,
            })
        elif message.startswith("checkpoint"):
            event = "checkpoint"
        elif "database system is ready" in message:
            event = "ready"
        elif "database system was" in message and "recovery" in message:
            event = "recovery"
        elif "listening on" in message:
            event = "listen"
        elif level in ("ERROR", "FATAL", "PANIC"):
            event = "error"
        elif level == "WARNING":
            event = "warning"

        slow = duration_ms is not None and duration_ms >= SLOW_QUERY_MS

        return {
            "timestamp": d["timestamp"].replace(" ", "T", 1),
            "pid": int(d["pid"]),
            "level": level,
            "event": event,
            "message": message[:500],
            "table": table,
            "stmt_type": stmt_type,
            "duration_ms": duration_ms,
            "slow": slow,
            "normalized": normalized,
        }

    def _hour_key(self, ts: str) -> str:
        if not ts:
            return "unknown"
        if "T" in ts:
            date_part, time_part = ts.split("T", 1)
            hour = time_part[:2] if len(time_part) >= 2 else "00"
            return f"{date_part} {hour}:00"
        parts = ts.split()
        if len(parts) >= 2:
            hour = parts[1][:2] if len(parts[1]) >= 2 else "00"
            return f"{parts[0]} {hour}:00"
        return "unknown"

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        level_counter = Counter(e["level"] for e in entries)
        event_counter = Counter(e["event"] for e in entries)
        stmt_counter = Counter(e["stmt_type"] for e in entries if e.get("stmt_type"))
        table_counter = Counter(e["table"] for e in entries if e.get("table"))

        hourly = Counter()
        for e in entries:
            hourly[self._hour_key(e["timestamp"])] += 1

        hourly_stmts = Counter()
        hourly_errors = Counter()
        for e in entries:
            hk = self._hour_key(e["timestamp"])
            if e.get("stmt_type"):
                hourly_stmts[hk] += 1
            if e.get("level") in ("ERROR", "FATAL", "PANIC"):
                hourly_errors[hk] += 1

        checkpoints = [e for e in entries if e["event"] == "checkpoint"]
        ckpt_metrics = None
        hourly_ckpt = Counter()
        if checkpoints:
            write_times = []
            sync_times = []
            total_times = []
            buffers_written = []
            for e in checkpoints:
                msg = e["message"]
                wm = CKPT_WRITE.search(msg)
                sm_c = CKPT_SYNC.search(msg)
                tm = CKPT_TOTAL.search(msg)
                bm = CKPT_BUFFERS.search(msg)
                if wm:
                    write_times.append(float(wm.group(1)))
                if sm_c:
                    sync_times.append(float(sm_c.group(1)))
                if tm:
                    total_times.append(float(tm.group(1)))
                    hourly_ckpt[self._hour_key(e["timestamp"])] += 1
                if bm:
                    buffers_written.append(int(bm.group(1)))
            if total_times:
                ckpt_metrics = {
                    "count": len(checkpoints),
                    "total_avg": round(sum(total_times) / len(total_times), 3),
                    "total_max": round(max(total_times), 3),
                    "write_avg": round(sum(write_times) / len(write_times), 3) if write_times else 0,
                    "sync_avg": round(sum(sync_times) / len(sync_times), 3) if sync_times else 0,
                    "buffers_avg": round(sum(buffers_written) / len(buffers_written)) if buffers_written else 0,
                }

        durations = [e["duration_ms"] for e in entries if e.get("duration_ms") is not None]
        duration_stats = None
        if durations:
            durations_sorted = sorted(durations)
            n = len(durations_sorted)
            duration_stats = {
                "count": n,
                "avg": round(sum(durations) / n, 2),
                "min": round(durations_sorted[0], 2),
                "p50": round(durations_sorted[n // 2], 2),
                "p95": round(durations_sorted[int(n * 0.95)], 2) if n > 1 else round(durations_sorted[0], 2),
                "p99": round(durations_sorted[int(n * 0.99)], 2) if n > 1 else round(durations_sorted[0], 2),
                "max": round(durations_sorted[-1], 2),
            }

        slow_queries = [e for e in entries if e.get("slow")]
        slow_queries.sort(key=lambda e: e.get("duration_ms", 0), reverse=True)

        error_entries = [e for e in entries if e["level"] in ("ERROR", "FATAL", "PANIC")]
        warning_entries = [e for e in entries if e["level"] == "WARNING"]
        warning_fingerprints = Counter()
        for e in warning_entries:
            simplified = re.sub(r'\d+', 'N', e["message"])
            simplified = re.sub(r'"[^"]*"', '"X"', simplified)
            warning_fingerprints[simplified] += 1

        statement_entries = [e for e in entries if e["event"] == "statement"]
        unique_tables = set(e["table"] for e in statement_entries if e.get("table"))
        unique_pids = set(e["pid"] for e in entries if e["pid"])
        read_stmts = sum(1 for e in entries if e.get("stmt_type") == "SELECT")
        write_stmts = sum(1 for e in entries if e.get("stmt_type") in ("INSERT", "UPDATE", "DELETE", "COPY"))
        tx_stmts = sum(1 for e in entries if e.get("stmt_type") in ("BEGIN", "COMMIT", "ROLLBACK"))

        top_tables_by_duration = Counter()
        for e in statement_entries:
            if e.get("table") and e.get("duration_ms") is not None:
                top_tables_by_duration[e["table"]] += e["duration_ms"]

        # Query normalization — group by normalized form
        norm_counter = Counter()
        norm_examples = {}
        for e in statement_entries:
            if e.get("normalized"):
                nkey = e["normalized"][:200]
                norm_counter[nkey] += 1
                if nkey not in norm_examples:
                    norm_examples[nkey] = {
                        "normalized": nkey,
                        "count": 0,
                        "avg_duration_ms": 0,
                        "total_duration_ms": 0,
                        "sample_table": e.get("table"),
                        "sample_stmt_type": e.get("stmt_type"),
                    }
                norm_examples[nkey]["count"] += 1
                if e.get("duration_ms") is not None:
                    norm_examples[nkey]["total_duration_ms"] += e["duration_ms"]
        normalized_queries = []
        for nkey, data in norm_counter.most_common():
            ex = norm_examples[nkey]
            if ex["count"] > 0 and ex["total_duration_ms"] > 0:
                ex["avg_duration_ms"] = round(ex["total_duration_ms"] / ex["count"], 2)
            del ex["total_duration_ms"]
            normalized_queries.append(ex)

        # Lock analysis
        lock_events = self._lock_events
        lock_by_type = Counter()
        lock_by_hour = Counter()
        for le in lock_events:
            msg_lower = le["message"].lower()
            if "deadlock" in msg_lower:
                lock_by_type["deadlock"] += 1
            elif "timeout" in msg_lower:
                lock_by_type["timeout"] += 1
            elif "waiting" in msg_lower:
                lock_by_type["wait"] += 1
            else:
                lock_by_type["other"] += 1
            lock_by_hour[self._hour_key(le["timestamp"])] += 1

        # Autovacuum analysis
        av_events = self._autovacuum_events
        av_by_table = Counter(e["table"] for e in av_events if e.get("table"))
        av_by_hour = Counter()
        for e in av_events:
            av_by_hour[self._hour_key(e["timestamp"])] += 1

        # Replication analysis
        rep_events = self._replication_events
        rep_by_hour = Counter()
        lag_values = []
        for e in rep_events:
            rep_by_hour[self._hour_key(e["timestamp"])] += 1
            if e.get("lag_value"):
                try:
                    lag_values.append(float(e["lag_value"]))
                except (ValueError, TypeError):
                    pass

        rep_stats = None
        if lag_values:
            rep_stats = {
                "count": len(lag_values),
                "avg": round(sum(lag_values) / len(lag_values), 2),
                "max": round(max(lag_values), 2),
                "min": round(min(lag_values), 2),
            }

        return {
            "log_type": "postgres",
            "log_type_label": "PostgreSQL Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "_entries": self.entries,
            "_line_numbers": self._line_numbers,
            "summary": {
                "total_entries": parsed,
                "statements": event_counter.get("statement", 0),
                "errors": event_counter.get("error", 0),
                "warnings": event_counter.get("warning", 0),
                "checkpoints": event_counter.get("checkpoint", 0),
                "slow_queries": len(slow_queries),
                "read_queries": read_stmts,
                "write_queries": write_stmts,
                "tx_ops": tx_stmts,
                "unique_tables": len(unique_tables),
                "unique_pids": len(unique_pids),
                "lock_events": len(lock_events),
                "autovacuum_events": len(av_events),
                "replication_events": len(rep_events),
            },
            "charts": {
                "level_distribution": [
                    {"label": k, "value": v}
                    for k, v in level_counter.most_common()
                ],
                "stmt_type_distribution": [
                    {"label": k, "value": v}
                    for k, v in stmt_counter.most_common()
                ],
                "top_tables": [
                    {"label": t[:60], "value": c}
                    for t, c in table_counter.most_common()
                ],
                "hourly_timeline": [
                    {"label": h, "value": c}
                    for h, c in sorted(hourly.items())
                ],
                "hourly_stmts": [
                    {"label": h, "value": c}
                    for h, c in sorted(hourly_stmts.items())
                ],
                "hourly_errors": [
                    {"label": h, "value": c}
                    for h, c in sorted(hourly_errors.items())
                ],
                "top_warnings": [
                    {"label": msg[:80] + ("..." if len(msg) > 80 else ""), "value": c}
                    for msg, c in warning_fingerprints.most_common()
                ],
                "top_errors": [
                    {"label": e["message"][:120], "value": 1}
                    for e in error_entries
                ],
                "duration_histogram": _build_duration_histogram(durations) if durations else None,
                "top_tables_by_duration": [
                    {"label": t[:60], "value": round(v, 2)}
                    for t, v in top_tables_by_duration.most_common()
                ],
                "hourly_ckpt": [
                    {"label": h, "value": c}
                    for h, c in sorted(hourly_ckpt.items())
                ],
                "lock_by_type": [
                    {"label": k, "value": v}
                    for k, v in lock_by_type.most_common()
                ],
                "lock_by_hour": [
                    {"label": h, "value": c}
                    for h, c in sorted(lock_by_hour.items())
                ],
                "autovacuum_by_table": [
                    {"label": (t or "unknown")[:60], "value": v}
                    for t, v in av_by_table.most_common()
                ],
                "autovacuum_by_hour": [
                    {"label": h, "value": c}
                    for h, c in sorted(av_by_hour.items())
                ],
                "replication_by_hour": [
                    {"label": h, "value": c}
                    for h, c in sorted(rep_by_hour.items())
                ],
            },
            "checkpoint_metrics": ckpt_metrics,
            "duration_stats": duration_stats,
            "slow_queries": [
                {
                    "timestamp": e["timestamp"],
                    "pid": e["pid"],
                    "duration_ms": e["duration_ms"],
                    "table": e.get("table"),
                    "stmt_type": e.get("stmt_type"),
                    "message": e["message"][:300],
                }
                for e in slow_queries
            ],
            "normalized_queries": normalized_queries,
            "lock_events": [
                {
                    "timestamp": le["timestamp"],
                    "pid": le["pid"],
                    "level": le["level"],
                    "message": le["message"][:200],
                }
                for le in lock_events
            ],
            "lock_summary": {
                "total": len(lock_events),
                "by_type": dict(lock_by_type),
            },
            "autovacuum_events": [
                {
                    "timestamp": e["timestamp"],
                    "pid": e["pid"],
                    "table": e.get("table"),
                    "dead_tuples": e.get("dead_tuples"),
                    "live_tuples": e.get("live_tuples"),
                    "message": e["message"][:200],
                }
                for e in av_events
            ],
            "autovacuum_summary": {
                "total": len(av_events),
                "by_table": dict(av_by_table.most_common()),
            },
            "replication_events": [
                {
                    "timestamp": e["timestamp"],
                    "pid": e["pid"],
                    "level": e["level"],
                    "message": e["message"][:200],
                    "lag_value": e.get("lag_value"),
                    "lag_unit": e.get("lag_unit"),
                }
                for e in rep_events
            ],
            "replication_summary": {
                "total": len(rep_events),
                "lag_stats": rep_stats,
            },
            "tables": {
                "levels": [
                    {"level": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                    for k, v in level_counter.most_common()
                ],
                "statement_types": [
                    {"stmt_type": k, "count": v, "pct": round(v / sum(stmt_counter.values()) * 100, 2) if stmt_counter else 0}
                    for k, v in stmt_counter.most_common()
                ],
                "top_tables": [
                    {"table": t, "count": c, "pct": round(c / sum(table_counter.values()) * 100, 2) if table_counter else 0}
                    for t, c in table_counter.most_common()
                ],
                "error_samples": [
                    {"timestamp": e["timestamp"], "level": e["level"], "message": e["message"][:200], "_entry_idx": self.entries.index(e)}
                    for e in error_entries
                ],
                "warning_samples": [
                    {"timestamp": e["timestamp"], "level": "WARNING", "message": e["message"][:200]}
                    for e in warning_entries
                ],
            },
        }


def _build_duration_histogram(durations: list[float]) -> list[dict]:
    buckets = [
        ("< 1ms", 0, 1),
        ("1-10ms", 1, 10),
        ("10-50ms", 10, 50),
        ("50-100ms", 50, 100),
        ("100-500ms", 100, 500),
        ("500ms-1s", 500, 1000),
        ("1-5s", 1000, 5000),
        ("> 5s", 5000, float("inf")),
    ]
    result = []
    for label, lo, hi in buckets:
        count = sum(1 for d in durations if lo <= d < hi)
        if count > 0:
            result.append({"label": label, "value": count})
    return result
