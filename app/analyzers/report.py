import re
from app.parsers import PARSERS

TYPE_MARKERS = {
    "nginx_access": [
        re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'),
    ],
    "nginx_error": [
        re.compile(r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[\w+\]\s+\d+#\d+:'),
    ],
    "container": [
        re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+z?\s+(stdout|stderr)', re.I),
    ],
    "syslog": [
        re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+(\[\d+\])?:'),
        re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*\s+\S+\s+\S+(\[\d+\])?:'),
    ],
    "postgres": [
        re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+\[\d+\]\s+(?:LOG|WARNING|ERROR|FATAL|PANIC):'),
        re.compile(r'duration:\s*[\d.]+\s*ms\s+statement:'),
        re.compile(r'checkpoint (?:starting|complete):'),
        re.compile(r'database system (?:is ready|was)'),
    ],
    "api_backend": [
        re.compile(r'^\{'),
        re.compile(r'^\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}'),
    ],
}


def detect_log_type(raw: str) -> str | None:
    lines = raw.strip().splitlines()
    sample = lines[:50] if len(lines) > 50 else lines
    scores = {lt: 0 for lt in TYPE_MARKERS}

    for line in sample:
        line = line.strip()
        if not line:
            continue
        for lt, patterns in TYPE_MARKERS.items():
            for pat in patterns:
                if pat.search(line):
                    scores[lt] += 1
                    break

    if not any(scores.values()):
        return None

    best = max(scores, key=scores.get)
    if scores[best] < 2 or scores[best] < len(sample) * 0.1:
        return None
    return best


def parse_and_analyze(raw: str, log_type: str | None = None, exclude_ips: list[str] | None = None) -> dict:
    if not log_type or log_type == "auto":
        log_type = detect_log_type(raw)

    if not log_type:
        return {
            "error": "Could not auto-detect log type. Please select the log type manually.",
            "log_type": None,
        }

    if log_type not in PARSERS:
        return {"error": f"Unknown log type: {log_type}", "log_type": None}

    try:
        parser = PARSERS[log_type]()
        report = parser.parse(raw, exclude_ips=exclude_ips)
        report["detected_type"] = log_type
        if exclude_ips:
            report["excluded_ips"] = exclude_ips
        return report
    except Exception as exc:
        return {"error": f"Failed to parse {log_type} logs: {exc}", "log_type": log_type}
