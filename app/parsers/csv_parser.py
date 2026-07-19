import csv
import io
import re
from collections import Counter
from app.parsers.base import BaseParser

COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "date", "created_at", "occurred_at", "ts",
                   "@timestamp", "datetime", "log_date", "event_time", "event_timestamp",
                   "accessed_on", "request_time", "logged_at", "emitted_at"],
    "level":     ["level", "severity", "log_level", "logtype", "loglevel"],
    "message":   ["message", "msg", "description", "error", "details", "log", "text", "body"],
    "ip":        ["ip", "source_ip", "client_ip", "src_ip", "remote_addr", "client",
                   "remote_ip", "src", "host_ip", "http_x_forwarded_for",
                   "x_forwarded_for", "forwarded_for", "requester_ip"],
    "endpoint":  ["endpoint", "path", "url", "request_uri", "uri", "request_path",
                   "url_path", "route", "api_path", "request_url"],
    "method":    ["method", "http_method", "verb"],
    "status":    ["status", "status_code", "http_code", "response_code", "code"],
    "duration":  ["duration", "response_time", "rt", "latency", "elapsed",
                   "request_time", "upstream_response_time", "processing_time"],
    "bytes":     ["bytes", "body_bytes", "size", "bytes_sent", "response_size", "content_length"],
    "user":      ["user", "username", "user_name", "auth_user", "uuid",
                   "user_id", "accessed_by_id"],
}

LEVEL_PATTERNS = [
    (re.compile(r'\b(FATAL|PANIC)\b', re.I), "FATAL"),
    (re.compile(r'\b(ERROR|ERR)\b', re.I), "ERROR"),
    (re.compile(r'\b(WARN(?:ING)?)\b', re.I), "WARN"),
    (re.compile(r'\b(INFO)\b', re.I), "INFO"),
    (re.compile(r'\b(DEBUG|DBG)\b', re.I), "DEBUG"),
]


def _detect_level(value: str) -> str:
    if not value:
        return "UNKNOWN"
    for pat, level in LEVEL_PATTERNS:
        if pat.search(value):
            return level
    return "UNKNOWN"


class CsvParser(BaseParser):
    name = "csv"
    description = "CSV / tabular log data"

    def __init__(self):
        super().__init__()
        self._headers = []
        self._column_mapping = {}
        self._detected_columns = set()
        self._all_columns = []

    def _auto_map_columns(self, headers: list[str]) -> dict[str, str | None]:
        mapping = {}
        used_targets = set()
        candidates = []
        for header in headers:
            normalised = header.strip().lower().replace(" ", "_").replace("-", "_")
            for target, aliases in COLUMN_MAP.items():
                if normalised in aliases or normalised == target:
                    candidates.append((header, target))
                    break
        candidates.sort(key=lambda c: (-len(c[0]), c[0]))
        for header, target in candidates:
            if target not in used_targets:
                mapping[header] = target
                used_targets.add(target)
            else:
                mapping[header] = None
        for header in headers:
            if header not in mapping:
                mapping[header] = None
        return mapping

    def parse(self, raw: str, exclude_ips: list[str] | None = None) -> dict:
        import time
        t0 = time.time()
        lines = raw.strip().splitlines()
        self._raw_lines = lines
        self.entries = []
        self._line_numbers = []
        self.errors = 0

        if not lines:
            self.processing_ms = round((time.time() - t0) * 1000, 1)
            return self._build_report(0, 0)

        header_line = lines[0].strip()
        if not header_line:
            self.processing_ms = round((time.time() - t0) * 1000, 1)
            return self._build_report(0, 0)

        try:
            header_reader = csv.reader(io.StringIO(header_line))
            self._headers = [h.strip() for h in next(header_reader)]
        except Exception:
            self.errors = len([l for l in lines if l.strip()])
            self.processing_ms = round((time.time() - t0) * 1000, 1)
            return self._build_report(len(lines), 0)

        if len(self._headers) < 2:
            self.errors = len(lines)
            self.processing_ms = round((time.time() - t0) * 1000, 1)
            return self._build_report(len(lines), 0)

        self._column_mapping = self._auto_map_columns(self._headers)
        self._detected_columns = {v for v in self._column_mapping.values() if v}
        self._all_columns = list(self._headers)

        total = len(lines)
        for i, line in enumerate(lines[1:], start=1):
            line = line.strip()
            if not line:
                continue
            entry = self._parse_csv_row(line)
            if entry:
                self.entries.append(entry)
                self._line_numbers.append(i)
            else:
                self.errors += 1

        parsed = len(self.entries)

        if exclude_ips:
            skip = set(exclude_ips)
            filtered = [
                (e, ln) for e, ln in zip(self.entries, self._line_numbers)
                if self._get_ip(e) not in skip
            ]
            self.entries = [e for e, _ in filtered]
            self._line_numbers = [ln for _, ln in filtered]
            parsed = len(self.entries)

        self.processing_ms = round((time.time() - t0) * 1000, 1)
        self._compute_time_range()
        return self._build_report(total, parsed)

    def _parse_csv_row(self, line: str) -> dict | None:
        try:
            reader = csv.reader(io.StringIO(line))
            values = next(reader)
        except Exception:
            return None

        entry = {}
        results_raw = None
        for idx, header in enumerate(self._headers):
            val = values[idx].strip() if idx < len(values) else None
            mapped = self._column_mapping.get(header) or header
            entry[mapped] = val if val else None
            if header == "results" and val:
                results_raw = val

        if "level" not in self._detected_columns and results_raw:
            self._extract_level_from_results(entry, results_raw)

        has_data = any(v is not None for v in entry.values())
        return entry if has_data else None

    @staticmethod
    def _extract_level_from_results(entry: dict, raw: str):
        low = raw.lower()
        if "'error'" in low or "'non_field_errors'" in low or "'detail'" in low:
            entry["level"] = "ERROR"
            m = re.search(r"'error':\s*'([^']*)'", raw)
            if not m:
                m = re.search(r"'detail':\s*ErrorDetail\(string='([^']*)'", raw)
            if not m:
                m = re.search(r"'non_field_errors':\s*\[ErrorDetail\(string='([^']*)'", raw)
            entry["message"] = m.group(1) if m else raw[:200]
        elif "'matched': 'Y'" in raw or "'matched': \"Y\"" in raw:
            entry["level"] = "INFO"
            entry["message"] = "Match found"
        elif "'matched': 'N'" in raw or "'matched': \"N\"" in raw:
            entry["level"] = "WARN"
            m = re.search(r"'error':\s*'([^']*)'", raw)
            entry["message"] = m.group(1) if m else "No match"
        elif "'token'" in low:
            entry["level"] = "INFO"
            entry["message"] = "Token issued"

    def _parse_line(self, line: str) -> dict | None:
        return self._parse_csv_row(line)

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        detected = set(self._detected_columns)
        if entries and any(e.get("level") for e in entries):
            detected.add("level")
        if entries and any(e.get("message") for e in entries):
            detected.add("message")

        summary = {
            "total_entries": parsed,
            "columns": sorted(detected),
            "all_columns": list(self._all_columns),
        }

        charts = {}
        tables = {}

        if "timestamp" in detected:
            hourly = Counter()
            for e in entries:
                ts = e.get("timestamp", "")
                if ts:
                    hourly[self._hour_key(ts)] += 1
            charts["hourly_timeline"] = [
                {"label": h, "value": c} for h, c in sorted(hourly.items())
            ]

        if "level" in detected:
            levels = Counter(e.get("level", "UNKNOWN") for e in entries)
            charts["level_distribution"] = [
                {"label": k, "value": v} for k, v in levels.most_common()
            ]
            tables["level_summary"] = [
                {"level": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                for k, v in levels.most_common()
            ]
            error_count = sum(
                v for k, v in levels.items()
                if k in ("ERROR", "FATAL", "CRITICAL")
            )
            summary["error_count"] = error_count
            summary["error_rate"] = round(error_count / parsed * 100, 2) if parsed else 0

            errors = [
                e for e in entries
                if (e.get("level") or "").upper() in ("ERROR", "FATAL", "CRITICAL")
            ]
            if errors:
                tables["error_samples"] = [
                    {k: e.get(k, "") for k in ["timestamp", "level", "message"] if e.get(k) is not None}
                    | {"_entry_idx": entries.index(e)}
                    for e in errors[:25]
                ]

        if "status" in detected:
            statuses = Counter(str(e.get("status", "")) for e in entries)
            charts["status_distribution"] = [
                {"label": k, "value": v} for k, v in statuses.most_common()
            ]
            tables["status_summary"] = [
                {"status": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                for k, v in statuses.most_common()
            ]

        if "method" in detected:
            methods = Counter(e.get("method", "UNKNOWN") for e in entries if e.get("method"))
            charts["method_distribution"] = [
                {"label": k, "value": v} for k, v in methods.most_common()
            ]

        if "duration" in detected:
            durations = []
            for e in entries:
                raw = e.get("duration")
                if raw:
                    try:
                        durations.append(float(raw))
                    except (ValueError, TypeError):
                        pass
            if durations:
                durations.sort()
                summary["avg_duration"] = round(sum(durations) / len(durations), 2)
                summary["p95_duration"] = round(durations[int(len(durations) * 0.95)], 2)
                summary["p99_duration"] = round(durations[int(len(durations) * 0.99)], 2)
                summary["max_duration"] = round(max(durations), 2)
                summary["min_duration"] = round(min(durations), 2)
                max_dur = max(durations) if durations else 1
                step = max_dur / 10 if max_dur > 0 else 1
                buckets = [0] * 10
                for d in durations:
                    idx = min(int(d / step), 9)
                    buckets[idx] += 1
                charts["duration_histogram"] = [
                    {
                        "label": f"{round(i * step, 1)}-{round((i + 1) * step, 1)}",
                        "value": buckets[i],
                    }
                    for i in range(10)
                ]

        if "ip" in detected:
            ips = Counter(e.get("ip", "") for e in entries if e.get("ip"))
            charts["top_ips"] = [
                {"label": k, "value": v} for k, v in ips.most_common(15)
            ]
            tables["ip_summary"] = [
                {"ip": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                for k, v in ips.most_common(20)
            ]
            summary["unique_ips"] = len(ips)

        if "endpoint" in detected:
            endpoints = Counter(e.get("endpoint", "") for e in entries if e.get("endpoint"))
            charts["top_endpoints"] = [
                {"label": k[:80], "value": v} for k, v in endpoints.most_common(15)
            ]
            tables["endpoint_summary"] = [
                {"endpoint": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                for k, v in endpoints.most_common(20)
            ]
            summary["unique_endpoints"] = len(endpoints)

        if "bytes" in detected:
            byte_vals = []
            for e in entries:
                raw = e.get("bytes")
                if raw:
                    try:
                        byte_vals.append(float(raw))
                    except (ValueError, TypeError):
                        pass
            if byte_vals:
                total_bytes = sum(byte_vals)
                summary["total_bytes"] = round(total_bytes)
                summary["total_bytes_human"] = self._human_bytes(total_bytes)

        tables["all_rows"] = entries[:500]

        return {
            "log_type": "csv",
            "log_type_label": "CSV Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "_entries": self.entries,
            "_line_numbers": self._line_numbers,
            "summary": summary,
            "charts": charts,
            "tables": tables,
        }

    @staticmethod
    def _human_bytes(n: float) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(n) < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"
