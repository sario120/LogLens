import re
from collections import Counter
from app.parsers.base import BaseParser
from app.config import MAX_STORED_ENTRIES

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

SEVERITY_KEYWORDS = [
    (re.compile(r'\bPANIC\b', re.I), "FATAL"),
    (re.compile(r'\bFATAL\b', re.I), "FATAL"),
    (re.compile(r'level=(?:error|crit|fatal)', re.I), "ERROR"),
    (re.compile(r'\bERROR\b', re.I), "ERROR"),
    (re.compile(r'level=warning', re.I), "WARN"),
    (re.compile(r'\bWARNING\b', re.I), "WARN"),
    (re.compile(r'level=notice', re.I), "NOTICE"),
    (re.compile(r'level=debug', re.I), "DEBUG"),
    (re.compile(r'\bDEBUG\b', re.I), "DEBUG"),
    (re.compile(r'level=info', re.I), "INFO"),
]

SERVICE_CATEGORIES = {
    "kernel": ["kernel", "i915", "drm"],
    "system": ["systemd", "systemd-logind", "systemd-sysusers", "systemd-modules-load",
               "systemd-journald", "systemd-resolved", "systemd-timesyncd",
               "systemd-tmpfiles", "udevd", "ModemManager"],
    "network": ["NetworkManager", "networkd", "wpa_supplicant", "dhclient", "polkitd"],
    "security": ["sshd", "sudo", "pam_unix", "pam_systemd", "fwupd"],
    "cron": ["CRON", "atd", "anacron"],
    "mail": ["postfix", "sendmail"],
    "package": ["PackageKit", "apt", "dpkg", "unattended-upgrades"],
    "monitoring": ["newrelic", "prometheus", "grafana", "node_exporter", "telegraf",
                   "amazon-ssm-agent"],
    "desktop": ["gnome-shell", "gnome-session", "gdm", "Xwayland", "mutter",
                "gjs", "Xorg", "xdg-desktop-portal"],
}

KERNEL_TRACE_START = re.compile(
    r'(?:WARNING:|BUG:|Call Trace:|---\[ cut here \]|Modules linked in:|'
    r'RIP:|Code:|Hardware name:|Tainted:|Workqueue:)',
    re.I,
)

LEVEL_MSG_EXTRACT = re.compile(
    r'(?:^|[\s;])(?:level|lvl|severity)\s*=\s*(debug|info|notice|warning|warn|error|err|crit|fatal|panic)',
    re.I,
)


ANOMALY_PATTERNS = [
    ("kernel_warning", re.compile(r'\bWARNING:.*drivers/', re.I), "Kernel driver warning"),
    ("kernel_warning", re.compile(r'drm_WARN_ON', re.I), "DRM assertion failure"),
    ("kernel_warning", re.compile(r'\bTainted:\s*\[W\]', re.I), "Kernel tainted with WARN flag"),
    ("kernel_bug", re.compile(r'\bBUG:', re.I), "Kernel BUG triggered"),
    ("kernel_oops", re.compile(r'\bRIP:\s', re.I), "Kernel RIP (possible oops)"),

    ("service_failure", re.compile(r'systemd\[1\].*\bFailed\b', re.I), "systemd service failure"),
    ("service_failure", re.compile(r'exited with status [1-9]', re.I), "Process exited with error status"),
    ("service_crash_loop", re.compile(r'systemd\[1\].*Deactivated successfully', re.I), "Service deactivated (watch for restart loop)"),

    ("display_server", re.compile(r'Xwayland.*exited unexpectedly', re.I), "Xwayland crash"),
    ("display_server", re.compile(r'GDM.*assertion.*failed', re.I), "GDM assertion failure"),
    ("display_server", re.compile(r'gnome-shell.*assertion.*failed', re.I), "GNOME Shell assertion failure"),
    ("display_server", re.compile(r'Unable to register client', re.I), "GNOME session registration failure"),

    ("application_error", re.compile(r'GLib-\w+\s*\*\*', re.I), "GLib critical error"),
    ("application_error", re.compile(r'assertion\s+.*failed', re.I), "Assertion failure"),
    ("application_error", re.compile(r'\bError\b.*failed', re.I), "Application error"),

    ("network_issue", re.compile(r'(?:timed?\s*out|timeout)', re.I), "Network/service timeout"),
    ("network_issue", re.compile(r'(?:unreachable|refused|reset)', re.I), "Network unreachable/refused"),
    ("network_issue", re.compile(r'carrier (?:error|lost)', re.I), "Network carrier issue"),

    ("security", re.compile(r'Failed password', re.I), "SSH failed password"),
    ("security", re.compile(r'authentication failure', re.I), "Authentication failure"),
    ("security", re.compile(r'invalid user', re.I), "Invalid user login attempt"),
    ("security", re.compile(r'(?:permission|access) denied', re.I), "Permission/access denied"),
    ("security", re.compile(r'sudo:.*NOT in sudoers', re.I), "Unauthorized sudo attempt"),

    ("hardware", re.compile(r'i915.*WARN', re.I), "Intel GPU driver warning"),
    ("hardware", re.compile(r'timeout waiting for PHY', re.I), "PHY ready timeout"),
    ("hardware", re.compile(r'MCE', re.I), "Machine Check Exception"),
    ("hardware", re.compile(r'thermal', re.I), "Thermal event"),

    ("livepatch", re.compile(r'livepatch.*failed', re.I), "Livepatch update failure"),
    ("livepatch", re.compile(r'POST request.*livepatch', re.I), "Livepatch API failure"),

    ("oom", re.compile(r'out of memory', re.I), "Out of memory"),
    ("oom", re.compile(r'killed process', re.I), "OOM killer invoked"),

    ("filesystem", re.compile(r'I/O error', re.I), "Disk I/O error"),
    ("filesystem", re.compile(r'ext4.*error', re.I), "ext4 filesystem error"),
    ("filesystem", re.compile(r'xfs.*error', re.I), "XFS filesystem error"),
]


def _detect_severity(message: str) -> str:
    for pat, level in SEVERITY_KEYWORDS:
        if pat.search(message):
            return level
    m = LEVEL_MSG_EXTRACT.search(message)
    if m:
        raw = m.group(1).upper()
        return raw.replace("ERR", "ERROR")
    return "INFO"


def _detect_service_category(process: str) -> str:
    proc_lower = process.lower()
    for category, keywords in SERVICE_CATEGORIES.items():
        for kw in keywords:
            if kw.lower() in proc_lower:
                return category
    return "other"


def _detect_anomaly(message: str, process: str, severity: str) -> tuple[str | None, str]:
    if severity in ("FATAL",):
        return "fatal_error", f"Fatal: {message[:120]}"

    for anomaly_type, pattern, description in ANOMALY_PATTERNS:
        if pattern.search(message):
            return anomaly_type, description

    if severity == "ERROR":
        return "generic_error", f"Error from {process}: {message[:120]}"
    if severity == "WARN" and not message.startswith("level="):
        return "generic_warning", f"Warning from {process}: {message[:120]}"

    return None, ""


def _fingerprint_message(message: str) -> str:
    simplified = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'N.N.N.N', message)
    simplified = re.sub(r'\b0x[0-9a-fA-F]+\b', 'HEX', simplified)
    simplified = re.sub(r'\b[0-9a-fA-F]{8,}\b', 'HASH', simplified)
    simplified = re.sub(r'\b\d+\b', 'N', simplified)
    simplified = re.sub(r'\s+', ' ', simplified)
    return simplified[:200]


class SyslogParser(BaseParser):
    name = "syslog"
    description = "Linux syslog, /var/log/auth.log, messages, secure (BSD + rsyslog formats)"

    def __init__(self):
        super().__init__()
        self._in_kernel_trace = False
        self._trace_start_idx = -1
        self._trace_line_count = 0

    def _parse_line(self, line: str) -> dict | None:
        if self._in_kernel_trace:
            self._trace_line_count += 1
            if self._is_trace_continuation(line):
                return None
            else:
                if self.entries and self.entries[-1].get("event") == "kernel_trace":
                    self.entries[-1]["trace_line_count"] = self._trace_line_count
                self._in_kernel_trace = False
                self._trace_line_count = 0

        m = RSYSLOG_PATTERN.match(line) or BSD_PATTERN.match(line)
        if not m:
            return None
        d = m.groupdict()
        message = d["message"]
        process = d["process"]
        is_auth_fail = any(p.search(message) for p in AUTH_FAIL_PATTERNS)
        ip_match = IP_EXTRACT.search(message)
        user_match = USER_EXTRACT.search(message)
        severity = _detect_severity(message)
        if is_auth_fail and severity == "INFO":
            severity = "WARN"
        category = _detect_service_category(process)

        anomaly_type, anomaly_detail = _detect_anomaly(message, process, severity)

        is_kernel_trace = False
        if category == "kernel" and KERNEL_TRACE_START.search(message):
            is_kernel_trace = True
            self._in_kernel_trace = True
            self._trace_line_count = 0
            if not anomaly_type:
                anomaly_type = "kernel_trace_block"

        return {
            "timestamp": d["timestamp"],
            "hostname": d["hostname"],
            "process": process,
            "pid": int(d["pid"]) if d.get("pid") else None,
            "message": message,
            "severity": severity,
            "category": category,
            "is_auth_failure": is_auth_fail,
            "source_ip": ip_match.group(1) if ip_match else None,
            "user": user_match.group(1) if user_match else None,
            "trace_line_count": 1 if is_kernel_trace else 0,
            "anomaly_type": anomaly_type,
            "anomaly_detail": anomaly_detail,
        }

    @staticmethod
    def _is_trace_continuation(line: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return False
        if KERNEL_TRACE_START.search(stripped):
            return False
        if stripped.startswith("Call Trace:"):
            return True
        if re.match(r'\s+<TASK>', stripped):
            return True
        if re.match(r'\s+\S+\+0x[0-9a-f]+/0x[0-9a-f]+', stripped):
            return True
        if re.match(r'\s+\? __pfx_', stripped):
            return True
        if re.match(r'\s+(RAX|RBX|RCX|RDX|RSI|RDI|RSP|RBP|R[0-9]+):', stripped):
            return True
        if re.match(r'\s+(RIP|EFLAGS|CS:|DS:|ES:|CR[0-4]:|FS:|GS:|PKRU):', stripped):
            return True
        if re.match(r'\s+(Code|Modules linked in):', stripped):
            return True
        if re.match(r'\s+---\[', stripped):
            return True
        if re.match(r'\s+\[ end trace', stripped):
            return True
        if re.match(r'\s+\d{4}[-/]\d{2}[-/]\d{2}T\d{2}:\d{2}:\d{2}.*\S+\s+kernel:', line):
            return False
        if "kernel:" in line and not stripped[0].isupper():
            return True
        return False

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        process_counter = Counter(e["process"] for e in entries)
        severity_counter = Counter(e["severity"] for e in entries)
        category_counter = Counter(e["category"] for e in entries)
        hostname_counter = Counter(e["hostname"] for e in entries if e.get("hostname"))
        auth_failures = [e for e in entries if e["is_auth_failure"]]
        ip_counter = Counter(e["source_ip"] for e in entries if e.get("source_ip"))
        user_counter = Counter(e["user"] for e in entries if e.get("user"))

        hourly = Counter()
        hourly_severity: dict[str, Counter] = {}
        for e in entries:
            hk = self._hour_key(e["timestamp"])
            hourly[hk] += 1
            if hk not in hourly_severity:
                hourly_severity[hk] = Counter()
            hourly_severity[hk][e["severity"]] += 1

        fail_msg_counter = Counter(e["message"][:100] for e in auth_failures)

        error_fingerprints = Counter()
        for e in entries:
            if e["severity"] in ("ERROR", "FATAL", "WARN"):
                error_fingerprints[_fingerprint_message(e["message"])] += 1

        trace_entries = [e for e in entries if e.get("trace_line_count", 0) > 0]
        total_trace_lines = sum(e["trace_line_count"] for e in trace_entries)

        anomalies = [e for e in entries if e.get("anomaly_type")]
        anomaly_counter = Counter(e["anomaly_type"] for e in anomalies)
        anomaly_fingerprints = Counter()
        for e in anomalies:
            fp = _fingerprint_message(e["message"])
            anomaly_fingerprints[fp] += 1

        anomaly_hourly = Counter()
        for e in anomalies:
            anomaly_hourly[self._hour_key(e["timestamp"])] += 1

        anomaly_samples = {}
        for e in anomalies:
            atype = e["anomaly_type"]
            if atype not in anomaly_samples:
                anomaly_samples[atype] = {
                    "type": atype,
                    "detail": e.get("anomaly_detail", ""),
                    "sample_message": e["message"][:200],
                    "count": 0,
                    "_entry_idx": entries.index(e),
                }
            anomaly_samples[atype]["count"] += 1

        return {
            "log_type": "syslog",
            "log_type_label": "Syslog / Auth Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "_entries": self.entries,
            "_line_numbers": self._line_numbers,
            "summary": {
                "total_entries": parsed,
                "unique_processes": len(process_counter),
                "auth_failures": len(auth_failures),
                "unique_source_ips": len(ip_counter),
                "unique_users_targeted": len(user_counter),
                "auth_failure_rate": round(len(auth_failures) / parsed * 100, 2) if parsed else 0,
                "kernel_warnings": sum(1 for e in entries if e["category"] == "kernel" and e["severity"] == "WARN"),
                "kernel_trace_blocks": len(trace_entries),
                "kernel_trace_lines": total_trace_lines,
                "error_count": severity_counter.get("ERROR", 0) + severity_counter.get("FATAL", 0),
                "warn_count": severity_counter.get("WARN", 0),
                "debug_count": severity_counter.get("DEBUG", 0),
                "unique_hostnames": len(hostname_counter),
                "total_anomalies": len(anomalies),
                "anomaly_types": len(anomaly_counter),
            },
            "severity_distribution": [
                {"label": k, "value": v} for k, v in severity_counter.most_common()
            ],
            "category_distribution": [
                {"label": k, "value": v} for k, v in category_counter.most_common()
            ],
            "anomaly_summary": [
                {"type": k, "count": v, "pct": round(v / parsed * 100, 2) if parsed else 0}
                for k, v in anomaly_counter.most_common()
            ],
            "charts": {
                "process_distribution": [{"label": k, "value": v} for k, v in process_counter.most_common()],
                "hourly_timeline": [{"label": h, "value": c} for h, c in sorted(hourly.items())],
                "top_source_ips": [{"label": ip, "value": v} for ip, v in ip_counter.most_common()],
                "top_targeted_users": [{"label": u, "value": v} for u, v in user_counter.most_common()],
                "auth_fail_messages": [
                    {"label": msg[:80] + ("..." if len(msg) > 80 else ""), "value": c}
                    for msg, c in fail_msg_counter.most_common()
                ],
                "top_errors": [
                    {"label": fp[:80] + ("..." if len(fp) > 80 else ""), "value": c}
                    for fp, c in error_fingerprints.most_common(20)
                ],
                "category_distribution": [
                    {"label": k, "value": v} for k, v in category_counter.most_common()
                ],
                "severity_distribution": [
                    {"label": k, "value": v} for k, v in severity_counter.most_common()
                ],
                "anomaly_timeline": [
                    {"label": h, "value": c} for h, c in sorted(anomaly_hourly.items())
                ],
                "anomaly_types": [
                    {"label": k, "value": v} for k, v in anomaly_counter.most_common()
                ],
            },
            "tables": {
                "processes": [
                    {"process": p, "count": c, "pct": round(c / parsed * 100, 2) if parsed else 0}
                    for p, c in process_counter.most_common()
                ],
                "auth_failures_detail": [
                    {"timestamp": e["timestamp"], "source_ip": e.get("source_ip", "-"),
                     "user": e.get("user", "-"), "message": e["message"][:150], "_entry_idx": self.entries.index(e)}
                    for e in auth_failures
                ],
                "top_source_ips": [
                    {"ip": ip, "count": c}
                    for ip, c in ip_counter.most_common()
                ],
                "error_samples": [
                    {"timestamp": e["timestamp"], "level": e["severity"],
                     "message": e["message"][:200], "_entry_idx": self.entries.index(e)}
                    for e in entries
                    if e["severity"] in ("ERROR", "FATAL")
                ][:500],
                "anomaly_samples": list(anomaly_samples.values()),
                "anomaly_fingerprints": [
                    {"fingerprint": fp[:120] + ("..." if len(fp) > 120 else ""), "count": c}
                    for fp, c in anomaly_fingerprints.most_common(50)
                ],
            },
        }
