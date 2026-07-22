import csv
import io
import re
import time
from collections import Counter
from app.parsers.base import BaseParser
from app.config import MAX_STORED_ENTRIES

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
        self._source_file = None
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

    def parse_file(self, filepath: str, exclude_ips: list[str] | None = None) -> dict:
        t0 = time.time()
        self._source_file = filepath
        self._raw_lines = []
        self.entries = []
        self._line_numbers = []
        self.errors = 0

        try:
            with open(filepath, "r", errors="replace", newline="") as f:
                first_line = f.readline()
                if not first_line.strip():
                    self.processing_ms = round((time.time() - t0) * 1000, 1)
                    return self._build_report(0, 0)
                header_reader = csv.reader(io.StringIO(first_line.strip()))
                self._headers = [h.strip() for h in next(header_reader)]
                if len(self._headers) < 2:
                    self.errors = 1
                    self.processing_ms = round((time.time() - t0) * 1000, 1)
                    return self._build_report(1, 0)
                self._column_mapping = self._auto_map_columns(self._headers)
                self._detected_columns = {v for v in self._column_mapping.values() if v}
                self._all_columns = list(self._headers)

                total = 1
                for i, line in enumerate(f, start=1):
                    total += 1
                    line = line.strip()
                    if not line:
                        continue
                    entry = self._parse_csv_row(line)
                    if entry:
                        if len(self.entries) < MAX_STORED_ENTRIES:
                            self.entries.append(entry)
                            self._line_numbers.append(i)
                    else:
                        self.errors += 1
        except Exception:
            self.processing_ms = round((time.time() - t0) * 1000, 1)
            return self._build_report(0, 0)

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

        # Check matched status first — matched='Y' overrides error field
        if "'matched': 'Y'" in raw or "'matched': \"Y\"" in raw:
            entry["level"] = "INFO"
            entry["message"] = "Match found"
            return

        if "'matched': 'N'" in raw or "'matched': \"N\"" in raw:
            entry["level"] = "WARN"
            m = re.search(r"'error':\s*'([^']*)'", raw)
            entry["message"] = m.group(1) if m else "No match"
            return

        # Check for non-empty error value (not just the key existing)
        m = re.search(r"'error':\s*'([^']+)'", raw)
        if m:
            entry["level"] = "ERROR"
            entry["message"] = m.group(1)
            return

        m = re.search(r"'detail':\s*ErrorDetail\(string='([^']*)'", raw)
        if m:
            entry["level"] = "ERROR"
            entry["message"] = m.group(1)
            return

        m = re.search(r"'non_field_errors':\s*\[ErrorDetail\(string='([^']*)'", raw)
        if m:
            entry["level"] = "ERROR"
            entry["message"] = m.group(1)
            return

        if "'token'" in low:
            entry["level"] = "INFO"
            entry["message"] = "Token issued"
            return

        # Fallback — has results dict but no match/error/token
        entry["level"] = "INFO"
        entry["message"] = raw[:200]

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
            daily = Counter()
            daily_by_level = {}
            for e in entries:
                ts = e.get("timestamp", "")
                if ts:
                    hourly[self._hour_key(ts)] += 1
                    day = self._day_key(ts)
                    daily[day] += 1
                    lvl = e.get("level", "UNKNOWN")
                    if day not in daily_by_level:
                        daily_by_level[day] = Counter()
                    daily_by_level[day][lvl] += 1
            charts["hourly_timeline"] = [
                {"label": h, "value": c} for h, c in sorted(hourly.items())
            ]
            charts["daily_timeline"] = [
                {"label": d, "value": c} for d, c in sorted(daily.items())
            ]
            daily_perf = []
            for d in sorted(daily.keys()):
                lvl_counts = daily_by_level.get(d, Counter())
                error_count = sum(v for k, v in lvl_counts.items()
                                  if k in ("ERROR", "FATAL", "CRITICAL"))
                warn_count = sum(v for k, v in lvl_counts.items() if k == "WARN")
                info_count = sum(v for k, v in lvl_counts.items() if k == "INFO")
                total_day = daily[d]
                daily_perf.append({
                    "date": d,
                    "requests": total_day,
                    "errors": error_count,
                    "warnings": warn_count,
                    "info": info_count,
                    "error_rate": round(error_count / total_day * 100, 2) if total_day else 0,
                })
            tables["daily_performance"] = daily_perf

        if "level" in detected:
            levels = Counter(e.get("level", "UNKNOWN") for e in entries)
            charts["level_distribution"] = [
                {"label": k, "value": v} for k, v in levels.most_common()
            ]
            tables["levels"] = [
                {"level": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                for k, v in levels.most_common()
            ]
            error_count = sum(
                v for k, v in levels.items()
                if k in ("ERROR", "FATAL", "CRITICAL")
            )
            summary["error_count"] = error_count
            summary["error_rate"] = round(error_count / parsed * 100, 2) if parsed else 0

            summary["matches_found"] = levels.get("INFO", 0)
            summary["no_match_count"] = levels.get("WARN", 0)

            errors = [
                e for e in entries
                if (e.get("level") or "").upper() in ("ERROR", "FATAL", "CRITICAL")
            ]
            if errors:
                tables["error_samples"] = [
                    {k: e.get(k, "") for k in ["timestamp", "level", "message"] if e.get(k) is not None}
                    | {"_entry_idx": entries.index(e)}
                    for e in errors
                ]

        if "message" in detected:
            messages = Counter(e.get("message", "UNKNOWN") for e in entries if e.get("message"))
            charts["message_distribution"] = [
                {"label": k[:80] + ("..." if len(k) > 80 else ""), "value": v}
                for k, v in messages.most_common()
            ]
            tables["message_summary"] = [
                {"message": k[:120], "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                for k, v in messages.most_common()
            ]

        if "status" in detected:
            statuses = Counter(str(e.get("status", "")) for e in entries)
            charts["status_distribution"] = [
                {"label": k, "value": v} for k, v in statuses.most_common()
            ]
            tables["status_codes"] = [
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
            ip_data = {}
            for e in entries:
                ip = e.get("ip")
                if not ip:
                    continue
                if ip not in ip_data:
                    ip_data[ip] = {
                        "total": 0, "endpoints": Counter(), "methods": Counter(),
                        "levels": Counter(), "users": set(),
                        "first_seen": e.get("timestamp", ""),
                        "last_seen": e.get("timestamp", ""),
                    }
                det = ip_data[ip]
                det["total"] += 1
                if e.get("endpoint"):
                    det["endpoints"][e["endpoint"]] += 1
                if e.get("method"):
                    det["methods"][e["method"]] += 1
                if e.get("level"):
                    det["levels"][e["level"]] += 1
                if e.get("user"):
                    det["users"].add(e["user"])
                ts = e.get("timestamp", "")
                if ts and (not det["last_seen"] or ts > det["last_seen"]):
                    det["last_seen"] = ts
                if ts and (not det["first_seen"] or ts < det["first_seen"]):
                    det["first_seen"] = ts

            ip_table = []
            for ip, det in ip_data.items():
                error_count = sum(v for k, v in det["levels"].items()
                                  if k in ("ERROR", "FATAL", "CRITICAL"))
                ip_table.append({
                    "ip": ip,
                    "total": det["total"],
                    "first_seen": det["first_seen"],
                    "last_seen": det["last_seen"],
                    "endpoints": dict(det["endpoints"].most_common()),
                    "methods": dict(det["methods"].most_common()),
                    "error_count": error_count,
                    "error_rate": round(error_count / det["total"] * 100, 2) if det["total"] else 0,
                    "unique_users": len(det["users"]),
                    "status_codes": dict(det["levels"].most_common()),
                })
            ip_table.sort(key=lambda x: x["total"], reverse=True)

            ips = Counter(e.get("ip", "") for e in entries if e.get("ip"))
            charts["top_ips"] = [
                {"label": k, "value": v} for k, v in ips.most_common()
            ]
            tables["ip_details"] = ip_table
            summary["unique_ips"] = len(ips)

        if "endpoint" in detected:
            ep_data = {}
            for e in entries:
                ep = e.get("endpoint")
                if not ep:
                    continue
                if ep not in ep_data:
                    ep_data[ep] = {
                        "total": 0, "ips": Counter(), "methods": Counter(),
                        "levels": Counter(), "users": set(),
                    }
                det = ep_data[ep]
                det["total"] += 1
                if e.get("ip"):
                    det["ips"][e["ip"]] += 1
                if e.get("method"):
                    det["methods"][e["method"]] += 1
                if e.get("level"):
                    det["levels"][e["level"]] += 1
                if e.get("user"):
                    det["users"].add(e["user"])

            ep_table = []
            for ep, det in ep_data.items():
                error_count = sum(v for k, v in det["levels"].items()
                                  if k in ("ERROR", "FATAL", "CRITICAL"))
                ep_table.append({
                    "endpoint": ep,
                    "total": det["total"],
                    "unique_ips": len(det["ips"]),
                    "top_ips": dict(det["ips"].most_common()),
                    "methods": dict(det["methods"].most_common()),
                    "error_count": error_count,
                    "error_rate": round(error_count / det["total"] * 100, 2) if det["total"] else 0,
                    "unique_users": len(det["users"]),
                })
            ep_table.sort(key=lambda x: x["total"], reverse=True)

            endpoints = Counter(e.get("endpoint", "") for e in entries if e.get("endpoint"))
            charts["top_endpoints"] = [
                {"label": k[:80], "value": v} for k, v in endpoints.most_common()
            ]
            tables["endpoint_details"] = ep_table
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

        tables["all_rows"] = entries

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
