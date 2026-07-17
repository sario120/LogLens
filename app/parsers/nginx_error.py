import re
from collections import Counter
from app.parsers.base import BaseParser, MONTH_MAP

PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>\w+)\] '
    r'(?P<pid>\d+)#(?P<tid>\d+):'
    r'(?: \*(?P<cid>\d+))? '
    r'(?P<message>.+)'
)

CLIENT_PATTERNS = [
    re.compile(r'client:\s*(?P<client>\S+)'),
    re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
]

def _parse_nginx_time(ts: str) -> str:
    parts = ts.split()
    if len(parts) >= 2:
        day_parts = parts[0].split("/")
        if len(day_parts) == 3:
            if day_parts[0].isdigit() and len(day_parts[0]) == 4:
                return f"{day_parts[0]}-{int(day_parts[1]):02d}-{int(day_parts[2]):02d}T{parts[1]}"
            return f"{day_parts[2]}-{MONTH_MAP.get(day_parts[1], 0):02d}-{int(day_parts[0]):02d}T{parts[1]}"
    return ts


def _extract_client(message: str) -> str | None:
    for pat in CLIENT_PATTERNS:
        m = pat.search(message)
        if m:
            val = m.group("client") or m.group("ip")
            return val.rstrip(",") if val else None
    return None


class NginxErrorParser(BaseParser):
    name = "nginx_error"
    description = "Nginx error logs"

    def _parse_line(self, line: str) -> dict | None:
        m = PATTERN.match(line)
        if not m:
            return None
        d = m.groupdict()
        return {
            "timestamp": _parse_nginx_time(d["timestamp"]),
            "level": d["level"],
            "pid": int(d["pid"]),
            "tid": int(d["tid"]),
            "cid": int(d["cid"]) if d.get("cid") else None,
            "client": _extract_client(d["message"]),
            "message": d["message"],
        }

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        level_counter = Counter(e["level"] for e in entries)
        client_counter = Counter(e["client"] for e in entries if e.get("client"))

        message_fingerprints = Counter()
        for e in entries:
            msg = e["message"]
            simplified = re.sub(r'\d+', 'N', msg)
            simplified = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'N.N.N.N', simplified)
            message_fingerprints[simplified] += 1

        hourly = Counter()
        for e in entries:
            hourly[self._hour_key(e["timestamp"])] += 1

        level_order = {"emerg": 0, "alert": 1, "crit": 2, "error": 3, "warn": 4, "notice": 5, "info": 6, "debug": 7}
        level_table = [
            {"level": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0, "severity": level_order.get(k, 5)}
            for k, v in level_counter.most_common()
        ]
        level_table.sort(key=lambda x: x["severity"])

        return {
            "log_type": "nginx_error",
            "log_type_label": "Nginx Error Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "summary": {
                "total_errors": parsed,
                "unique_clients": len(client_counter),
                "crit_count": level_counter.get("crit", 0) + level_counter.get("emerg", 0) + level_counter.get("alert", 0),
                "error_count": level_counter.get("error", 0),
                "warn_count": level_counter.get("warn", 0),
            },
            "charts": {
                "level_distribution": [{"label": k, "value": v} for k, v in level_counter.most_common()],
                "hourly_timeline": [{"label": h, "value": c} for h, c in sorted(hourly.items())],
                "top_clients": [{"label": c, "value": v} for c, v in client_counter.most_common(10)],
                "top_messages": [
                    {"label": msg[:80] + ("..." if len(msg) > 80 else ""), "value": c}
                    for msg, c in message_fingerprints.most_common(15)
                ],
            },
            "tables": {
                "levels": level_table,
                "top_clients": [
                    {"client": c, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                    for c, v in client_counter.most_common(15)
                ],
                "top_messages": [
                    {"message": msg[:120], "count": c}
                    for msg, c in message_fingerprints.most_common(20)
                ],
            },
        }
