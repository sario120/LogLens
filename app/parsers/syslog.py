import re
from collections import Counter
from app.parsers.base import BaseParser

BSD_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    r'\s+(?P<hostname>\S+)'
    r'\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:'
    r'\s+(?P<message>.+)'
)

RSYSLOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)'
    r'\s+(?P<hostname>\S+)'
    r'\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:'
    r'\s+(?P<message>.+)'
)

AUTH_FAIL_PATTERNS = [
    re.compile(r'Failed password', re.I),
    re.compile(r'authentication failure', re.I),
    re.compile(r'invalid user', re.I),
    re.compile(r'connection closed.*preauth', re.I),
    re.compile(r'not valid', re.I),
    re.compile(r'refused', re.I),
    re.compile(r'failed', re.I),
    re.compile(r'unauthorized', re.I),
]

IP_EXTRACT = re.compile(r'(?:(?:from|for|client)\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
USER_EXTRACT = re.compile(r'(?:user|from)\s+(\S+)')

SEVERITY_MAP = {
    "auth": "critical", "sshd": "high", "sudo": "high",
    "cron": "low", "systemd": "info", "kernel": "warning",
}


class SyslogParser(BaseParser):
    name = "syslog"
    description = "Linux syslog, /var/log/auth.log, messages, secure (BSD + rsyslog formats)"

    def _parse_line(self, line: str) -> dict | None:
        m = RSYSLOG_PATTERN.match(line) or BSD_PATTERN.match(line)
        if not m:
            return None
        d = m.groupdict()
        is_auth_fail = any(p.search(d["message"]) for p in AUTH_FAIL_PATTERNS)
        ip_match = IP_EXTRACT.search(d["message"])
        user_match = USER_EXTRACT.search(d["message"])
        return {
            "timestamp": d["timestamp"],
            "hostname": d["hostname"],
            "process": d["process"],
            "pid": int(d["pid"]) if d.get("pid") else None,
            "message": d["message"],
            "is_auth_failure": is_auth_fail,
            "source_ip": ip_match.group(1) if ip_match else None,
            "user": user_match.group(1) if user_match else None,
        }

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        process_counter = Counter(e["process"] for e in entries)
        auth_failures = [e for e in entries if e["is_auth_failure"]]
        ip_counter = Counter(e["source_ip"] for e in entries if e.get("source_ip"))
        user_counter = Counter(e["user"] for e in entries if e.get("user"))

        hourly = Counter()
        for e in entries:
            hourly[self._hour_key(e["timestamp"])] += 1

        fail_msg_counter = Counter(e["message"] for e in auth_failures)

        return {
            "log_type": "syslog",
            "log_type_label": "Syslog / Auth Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "summary": {
                "total_entries": parsed,
                "unique_processes": len(process_counter),
                "auth_failures": len(auth_failures),
                "unique_source_ips": len(ip_counter),
                "unique_users_targeted": len(user_counter),
                "auth_failure_rate": round(len(auth_failures) / parsed * 100, 2) if parsed else 0,
            },
            "charts": {
                "process_distribution": [{"label": k, "value": v} for k, v in process_counter.most_common(15)],
                "hourly_timeline": [{"label": h, "value": c} for h, c in sorted(hourly.items())],
                "top_source_ips": [{"label": ip, "value": v} for ip, v in ip_counter.most_common(10)],
                "top_targeted_users": [{"label": u, "value": v} for u, v in user_counter.most_common(10)],
                "auth_fail_messages": [
                    {"label": msg[:80] + ("..." if len(msg) > 80 else ""), "value": c}
                    for msg, c in fail_msg_counter.most_common(10)
                ],
            },
            "tables": {
                "processes": [
                    {"process": p, "count": c, "pct": round(c / parsed * 100, 2) if parsed else 0}
                    for p, c in process_counter.most_common(15)
                ],
                "auth_failures_detail": [
                    {"timestamp": e["timestamp"], "source_ip": e.get("source_ip", "-"),
                     "user": e.get("user", "-"), "message": e["message"][:150]}
                    for e in auth_failures[:30]
                ],
                "top_source_ips": [
                    {"ip": ip, "count": c}
                    for ip, c in ip_counter.most_common(10)
                ],
            },
        }
