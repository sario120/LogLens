import re
from collections import Counter
from app.parsers.base import BaseParser

DOCKER_TS = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)'
    r'\s+(?P<stream>stdout|stderr)'
    r'(?:\s+(?P<flag>[A-Z]))?'
    r'\s+(?P<message>.+)'
)

LEVEL_PATTERNS = [
    (re.compile(r'\b(FATAL|PANIC)\b', re.I), "FATAL"),
    (re.compile(r'\b(ERROR|ERR)\b', re.I), "ERROR"),
    (re.compile(r'\b(WARN(?:ING)?)\b', re.I), "WARN"),
    (re.compile(r'\b(INFO)\b', re.I), "INFO"),
    (re.compile(r'\b(DEBUG|DBG)\b', re.I), "DEBUG"),
    (re.compile(r'\b TRACE \b', re.I), "TRACE"),
]


def _detect_level(message: str) -> str:
    for pat, level in LEVEL_PATTERNS:
        if pat.search(message):
            return level
    return "UNKNOWN"


class ContainerLogParser(BaseParser):
    name = "container"
    description = "Docker / containerd / Kubernetes pod logs"

    def _parse_line(self, line: str) -> dict | None:
        m = DOCKER_TS.match(line)
        if m:
            d = m.groupdict()
            return {
                "timestamp": d["timestamp"].replace("Z", ""),
                "stream": d["stream"],
                "flag": d.get("flag"),
                "level": _detect_level(d["message"]),
                "message": d["message"],
            }

        if len(line) > 20:
            return {
                "timestamp": "",
                "stream": "stdout",
                "flag": None,
                "level": _detect_level(line),
                "message": line,
            }
        return None

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        level_counter = Counter(e["level"] for e in entries)
        stream_counter = Counter(e["stream"] for e in entries)
        error_entries = [e for e in entries if e["level"] in ("ERROR", "FATAL")]

        hourly = Counter()
        for e in entries:
            hourly[self._hour_key(e["timestamp"])] += 1

        error_fingerprints = Counter()
        for e in error_entries:
            msg = e["message"]
            simplified = re.sub(r'\d+', 'N', msg)
            simplified = re.sub(r'\b[a-f0-9]{8,}\b', 'HASH', simplified, flags=re.I)
            error_fingerprints[simplified] += 1

        return {
            "log_type": "container",
            "log_type_label": "Container / Docker Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "summary": {
                "total_entries": parsed,
                "stdout_count": stream_counter.get("stdout", 0),
                "stderr_count": stream_counter.get("stderr", 0),
                "error_count": level_counter.get("ERROR", 0) + level_counter.get("FATAL", 0),
                "warn_count": level_counter.get("WARN", 0),
                "error_rate": round(
                    (level_counter.get("ERROR", 0) + level_counter.get("FATAL", 0)) / parsed * 100, 2
                ) if parsed else 0,
            },
            "charts": {
                "level_distribution": [{"label": k, "value": v} for k, v in level_counter.most_common()],
                "stream_distribution": [{"label": k, "value": v} for k, v in stream_counter.most_common()],
                "hourly_timeline": [{"label": h, "value": c} for h, c in sorted(hourly.items())],
                "top_errors": [
                    {"label": msg[:80] + ("..." if len(msg) > 80 else ""), "value": c}
                    for msg, c in error_fingerprints.most_common(15)
                ],
            },
            "tables": {
                "levels": [
                    {"level": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                    for k, v in level_counter.most_common()
                ],
                "error_samples": [
                    {"timestamp": e["timestamp"], "level": e["level"], "message": e["message"][:200]}
                    for e in error_entries[:25]
                ],
            },
        }
