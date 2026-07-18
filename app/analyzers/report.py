import re
from app.parsers import PARSERS
from app.config import DETECT_SAMPLE_SIZE

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


def detect_log_type(raw: str) -> tuple[str | None, float, dict[str, int]]:
    """Returns (detected_type, confidence, all_scores)."""
    lines = raw.strip().splitlines()
    sample = lines[:DETECT_SAMPLE_SIZE] if len(lines) > DETECT_SAMPLE_SIZE else lines
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

    total_matched = sum(scores.values())
    if not total_matched:
        return None, 0.0, scores

    best = max(scores, key=scores.get)
    if scores[best] < 2 or scores[best] < len(sample) * 0.1:
        return None, 0.0, scores

    confidence = round(min(1.0, scores[best] / max(len(sample), 1)), 2)
    return best, confidence, scores


def parse_and_analyze(raw: str, log_type: str | None = None, exclude_ips: list[str] | None = None, return_parser: bool = False):
    detection_confidence = None
    detection_scores = None
    if not log_type or log_type == "auto":
        log_type, detection_confidence, detection_scores = detect_log_type(raw)

    if not log_type:
        result = {
            "error": "Could not auto-detect log type. Please select the log type manually.",
            "log_type": None,
        }
        return (result, None) if return_parser else result

    if log_type not in PARSERS:
        result = {"error": f"Unknown log type: {log_type}", "log_type": None}
        return (result, None) if return_parser else result

    try:
        parser = PARSERS[log_type]()
        report = parser.parse(raw, exclude_ips=exclude_ips)
        report["detected_type"] = log_type
        if detection_confidence is not None:
            report["detection_confidence"] = detection_confidence
            report["detection_scores"] = {k: v for k, v in detection_scores.items() if v > 0}
        if exclude_ips:
            report["excluded_ips"] = exclude_ips
        return (report, parser) if return_parser else report
    except Exception as exc:
        result = {"error": f"Failed to parse {log_type} logs: {exc}", "log_type": log_type}
        return (result, None) if return_parser else result
