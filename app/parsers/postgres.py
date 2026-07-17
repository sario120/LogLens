import re
from collections import Counter
from app.parsers.base import BaseParser

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

SLOW_QUERY_MS = 1000.0


class PostgresParser(BaseParser):
    name = "postgres"
    description = "PostgreSQL logs (stderr format with timestamps)"

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
                event = "statement"
            else:
                event = "duration"
        elif message.startswith("statement:"):
            raw_stmt = message[len("statement:"):].strip()
            sm = STMT_TYPE.search(raw_stmt)
            stmt_type = sm.group(1).upper() if sm else "OTHER"
            table_m = TABLE_EXTRACT.search(raw_stmt)
            table = table_m.group(1) if table_m else None
            event = "statement"
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

        return {
            "log_type": "postgres",
            "log_type_label": "PostgreSQL Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
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
            },
            "charts": {
                "level_distribution": [
                    {"label": k, "value": v}
                    for k, v in level_counter.most_common()
                ],
                "stmt_type_distribution": [
                    {"label": k, "value": v}
                    for k, v in stmt_counter.most_common(10)
                ],
                "top_tables": [
                    {"label": t[:60], "value": c}
                    for t, c in table_counter.most_common(15)
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
                    for msg, c in warning_fingerprints.most_common(10)
                ],
                "top_errors": [
                    {"label": e["message"][:120], "value": 1}
                    for e in error_entries[:15]
                ],
                "duration_histogram": _build_duration_histogram(durations) if durations else None,
                "top_tables_by_duration": [
                    {"label": t[:60], "value": round(v, 2)}
                    for t, v in top_tables_by_duration.most_common(10)
                ],
                "hourly_ckpt": [
                    {"label": h, "value": c}
                    for h, c in sorted(hourly_ckpt.items())
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
                for e in slow_queries[:50]
            ],
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
                    for t, c in table_counter.most_common(20)
                ],
                "error_samples": [
                    {"timestamp": e["timestamp"], "level": e["level"], "message": e["message"][:200]}
                    for e in error_entries[:25]
                ],
                "warning_samples": [
                    {"timestamp": e["timestamp"], "level": "WARNING", "message": e["message"][:200]}
                    for e in warning_entries[:25]
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
