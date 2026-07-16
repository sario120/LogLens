import json
import re
from collections import Counter
from app.parsers.base import BaseParser

LEVEL_MAP = {"trace": 0, "debug": 1, "info": 2, "warn": 3, "warning": 3,
             "error": 4, "fatal": 5, "critical": 5}

TEXT_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
    r'\s+(?:\[(?P<level>\w+)\]|"level":\s*"(?P<level2>\w+)"|(?P<level3>ERROR|WARN|INFO|DEBUG|FATAL))'
)


class ApiBackendParser(BaseParser):
    name = "api_backend"
    description = "API backend logs (JSON structured or plain text with timestamps)"

    def _parse_line(self, line: str) -> dict | None:
        stripped = line.strip()
        if stripped.startswith("{"):
            return self._parse_json(stripped)
        return self._parse_text(stripped)

    def _parse_json(self, line: str) -> dict | None:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None
        level_raw = (d.get("level") or d.get("severity") or d.get("loglevel")
                     or d.get("log_level") or d.get("lvl") or "info")
        level = level_raw.lower() if isinstance(level_raw, str) else str(level_raw)
        ts = (d.get("timestamp") or d.get("time") or d.get("ts")
              or d.get("@timestamp") or d.get("date") or "")
        msg = d.get("message") or d.get("msg") or d.get("log") or d.get("error") or ""
        skip = {"timestamp", "time", "ts", "@timestamp", "date",
                "level", "severity", "loglevel", "log_level", "lvl",
                "message", "msg", "log", "error",
                "method", "http_method", "req_method",
                "path", "url", "uri", "endpoint",
                "status", "duration", "request_id", "req_id", "trace_id"}
        return {
            "timestamp": str(ts), "level": level,
            "method": d.get("method") or d.get("http_method") or d.get("req_method"),
            "path": d.get("path") or d.get("url") or d.get("uri") or d.get("endpoint"),
            "status": int(d["status"]) if "status" in d and d["status"] is not None else None,
            "duration": float(d["duration"]) if "duration" in d and d["duration"] is not None else None,
            "message": str(msg),
            "request_id": d.get("request_id") or d.get("req_id") or d.get("trace_id"),
            "extra": {k: v for k, v in d.items() if k not in skip},
        }

    def _parse_text(self, line: str) -> dict | None:
        m = TEXT_PATTERN.search(line)
        if not m:
            return None
        g = m.groupdict()
        level = g.get("level") or g.get("level2") or g.get("level3") or "info"
        return {
            "timestamp": g["timestamp"], "level": level.lower(),
            "method": None, "path": None, "status": None, "duration": None,
            "message": line, "request_id": None, "extra": {},
        }

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        level_counter = Counter(e["level"] for e in entries)
        method_counter = Counter(e["method"] for e in entries if e.get("method"))
        path_counter = Counter(e["path"] for e in entries if e.get("path"))
        status_counter = Counter(e["status"] for e in entries if e.get("status") is not None)
        duration_values = [e["duration"] for e in entries if e.get("duration") is not None]
        dur_sorted = sorted(duration_values) if duration_values else []

        hourly = Counter()
        for e in entries:
            hourly[self._hour_key(e["timestamp"])] += 1

        error_entries = [e for e in entries if e["level"] in ("error", "fatal", "critical")]
        error_msg_counter = Counter(e["message"][:100] for e in error_entries if e.get("message"))

        endpoint_stats = {}
        for e in entries:
            p = e.get("path")
            m = e.get("method")
            if not p:
                continue
            key = f"{m} {p}" if m else p
            if key not in endpoint_stats:
                endpoint_stats[key] = {"count": 0, "errors": 0, "durations": [], "statuses": Counter()}
            endpoint_stats[key]["count"] += 1
            if e["level"] in ("error", "fatal", "critical"):
                endpoint_stats[key]["errors"] += 1
            if e.get("duration") is not None:
                endpoint_stats[key]["durations"].append(e["duration"])
            if e.get("status") is not None:
                endpoint_stats[key]["statuses"][e["status"]] += 1

        endpoint_table = []
        for ep, st in endpoint_stats.items():
            durs = sorted(st["durations"])
            endpoint_table.append({
                "endpoint": ep, "count": st["count"], "errors": st["errors"],
                "error_rate": round(st["errors"] / st["count"] * 100, 2) if st["count"] else 0,
                "avg_duration": round(sum(durs) / len(durs), 3) if durs else None,
                "p95_duration": round(durs[int(len(durs) * 0.95)], 3) if durs else None,
                "max_duration": round(durs[-1], 3) if durs else None,
                "status_codes": dict(st["statuses"].most_common()),
            })
        endpoint_table.sort(key=lambda x: x["count"], reverse=True)

        return {
            "log_type": "api_backend",
            "log_type_label": "API Backend Log",
            "total_lines": total, "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "summary": {
                "total_entries": parsed,
                "error_count": sum(level_counter.get(lv, 0) for lv in ("error", "fatal", "critical")),
                "warn_count": level_counter.get("warn", 0) + level_counter.get("warning", 0),
                "unique_endpoints": len(path_counter),
                "error_rate": round(
                    sum(level_counter.get(lv, 0) for lv in ("error", "fatal", "critical")) / parsed * 100, 2
                ) if parsed else 0,
                "avg_duration": round(sum(dur_sorted) / len(dur_sorted), 3) if dur_sorted else None,
                "p95_duration": round(dur_sorted[int(len(dur_sorted) * 0.95)], 3) if dur_sorted else None,
                "p99_duration": round(dur_sorted[int(len(dur_sorted) * 0.99)], 3) if dur_sorted else None,
                "max_duration": round(dur_sorted[-1], 3) if dur_sorted else None,
            },
            "charts": {
                "level_distribution": [{"label": k, "value": v} for k, v in level_counter.most_common()],
                "hourly_timeline": [{"label": h, "value": c} for h, c in sorted(hourly.items())],
                "top_endpoints": [{"label": p, "value": c} for p, c in path_counter.most_common(15)],
                "method_distribution": [{"label": k, "value": v} for k, v in method_counter.most_common()],
                "status_distribution": [{"label": str(k), "value": v} for k, v in status_counter.most_common()],
                "duration_histogram": [
                    {"label": f"≤{round(dur_sorted[min(i + step, len(dur_sorted)) - 1], 2)}s", "value": min(i + step, len(dur_sorted)) - i}
                    for i in range(0, len(dur_sorted), max(1, len(dur_sorted) // 20))
                ] if dur_sorted else [],
                "top_errors": [
                    {"label": msg[:80] + ("..." if len(msg) > 80 else ""), "value": c}
                    for msg, c in error_msg_counter.most_common(15)
                ],
            },
            "tables": {
                "levels": [
                    {"level": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0,
                     "severity": LEVEL_MAP.get(k, 2)}
                    for k, v in level_counter.most_common()
                ],
                "endpoint_details": endpoint_table[:20],
                "error_samples": [
                    {"timestamp": e["timestamp"], "level": e["level"], "message": e["message"][:200]}
                    for e in error_entries[:25]
                ],
            },
        }
