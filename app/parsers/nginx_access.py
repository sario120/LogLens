import re
from collections import Counter, defaultdict
from app.parsers.base import BaseParser

PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
    r'(?: rt=(?P<response_time>\d+(?:\.\d+)?))?'
    r'(?: urt=(?P<upstream_response_time>\d+(?:\.\d+)?))?'
    r'(?: uht=(?P<upstream_header_time>\d+(?:\.\d+)?))?'
    r'(?: uct=(?P<upstream_connect_time>\d+(?:\.\d+)?))?'
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

SLOW_THRESHOLD = 10.0
CRITICAL_THRESHOLD = 30.0


def _parse_nginx_time(ts: str) -> str:
    parts = ts.split()
    if len(parts) < 2:
        return ts
    day_parts = parts[0].split("/")
    if len(day_parts) == 3:
        date_part = day_parts[2]
        if ":" in date_part:
            year, time = date_part.split(":", 1)
        else:
            year, time = date_part, parts[1] if len(parts) > 1 else "00:00:00"
        return f"{year}-{MONTH_MAP.get(day_parts[1], 0):02d}-{int(day_parts[0]):02d}T{time}"
    return ts


def _percentile(sorted_vals: list, p: float) -> float | None:
    if not sorted_vals:
        return None
    idx = int(len(sorted_vals) * p)
    return round(sorted_vals[min(idx, len(sorted_vals) - 1)], 3)


def _stats(values: list) -> dict:
    s = sorted(values)
    return {
        "count": len(s),
        "avg": round(sum(s) / len(s), 3) if s else None,
        "min": round(s[0], 3) if s else None,
        "p50": _percentile(s, 0.50),
        "p95": _percentile(s, 0.95),
        "p99": _percentile(s, 0.99),
        "max": round(s[-1], 3) if s else None,
    }


def _detect_incidents(hourly_rt: dict[str, list[float]], window: str = "hourly") -> list[dict]:
    incidents = []
    sorted_hours = sorted(hourly_rt.keys())
    for h in sorted_hours:
        vals = hourly_rt[h]
        if not vals:
            continue
        avg = sum(vals) / len(vals)
        p95 = _percentile(sorted(vals), 0.95) or 0
        mx = max(vals)
        error_count = sum(1 for v in vals if v > CRITICAL_THRESHOLD)
        if avg > SLOW_THRESHOLD or mx > CRITICAL_THRESHOLD:
            severity = "critical" if mx > CRITICAL_THRESHOLD or avg > CRITICAL_THRESHOLD else "degraded"
            incidents.append({
                "period": h,
                "severity": severity,
                "avg_rt": round(avg, 3),
                "p95_rt": round(p95, 3),
                "max_rt": round(mx, 3),
                "request_count": len(vals),
                "slow_count": error_count,
            })
    return incidents


def _safe_float(v: str | None) -> float | None:
    if not v:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


class NginxAccessParser(BaseParser):
    name = "nginx_access"
    description = "Nginx access logs (combined format with optional response times)"

    def _parse_line(self, line: str) -> dict | None:
        m = PATTERN.match(line)
        if not m:
            return None
        d = m.groupdict()
        bytes_val = d["bytes"]
        return {
            "ip": d["ip"],
            "timestamp": _parse_nginx_time(d["timestamp"]),
            "method": d["method"],
            "path": d["path"],
            "protocol": d.get("protocol", ""),
            "status": int(d["status"]),
            "bytes": int(bytes_val) if bytes_val != "-" else 0,
            "referrer": d.get("referrer", "-"),
            "user_agent": d.get("user_agent", "-"),
            "response_time": _safe_float(d.get("response_time")),
            "upstream_response_time": _safe_float(d.get("upstream_response_time")),
            "upstream_header_time": _safe_float(d.get("upstream_header_time")),
            "upstream_connect_time": _safe_float(d.get("upstream_connect_time")),
        }

    def _build_report(self, total: int, parsed: int) -> dict:
        entries = self.entries
        status_counter = Counter(e["status"] for e in entries)
        ip_counter = Counter(e["ip"] for e in entries)
        method_counter = Counter(e["method"] for e in entries)
        path_counter = Counter(e["path"] for e in entries)

        rt_values = [e["response_time"] for e in entries if e.get("response_time") is not None]
        urt_values = [e["upstream_response_time"] for e in entries if e.get("upstream_response_time") is not None]
        uht_values = [e["upstream_header_time"] for e in entries if e.get("upstream_header_time") is not None]
        uct_values = [e["upstream_connect_time"] for e in entries if e.get("upstream_connect_time") is not None]
        total_bytes = sum(e["bytes"] for e in entries)
        error_count = sum(v for k, v in status_counter.items() if k >= 400)

        hourly = Counter()
        hourly_rt: dict[str, list[float]] = defaultdict(list)
        for e in entries:
            ts = e["timestamp"]
            if "T" in ts:
                hour = ts.split("T")[1][:2] + ":00"
            else:
                hour = "unknown"
            hourly[hour] += 1
            if e.get("response_time") is not None:
                hourly_rt[hour].append(e["response_time"])

        endpoint_stats = defaultdict(lambda: {"rt_values": [], "statuses": Counter(), "count": 0})
        for e in entries:
            p = e["path"]
            endpoint_stats[p]["count"] += 1
            endpoint_stats[p]["statuses"][e["status"]] += 1
            if e.get("response_time") is not None:
                endpoint_stats[p]["rt_values"].append(e["response_time"])

        endpoint_table = []
        for path, det in endpoint_stats.items():
            s = _stats(det["rt_values"])
            errs = sum(v for k, v in det["statuses"].items() if k >= 400)
            endpoint_table.append({
                "path": path,
                "count": det["count"],
                "error_rate": round(errs / det["count"] * 100, 2) if det["count"] else 0,
                "rt": s,
            })
        endpoint_table.sort(key=lambda x: x["rt"]["avg"] or 0, reverse=True)

        ip_details = {}
        for e in entries:
            ip = e["ip"]
            if ip not in ip_details:
                ip_details[ip] = {
                    "total": 0, "methods": Counter(), "paths": Counter(),
                    "statuses": Counter(), "rt_values": [], "first_seen": e["timestamp"],
                    "last_seen": e["timestamp"], "total_bytes": 0,
                }
            det = ip_details[ip]
            det["total"] += 1
            det["methods"][e["method"]] += 1
            det["paths"][e["path"]] += 1
            det["statuses"][e["status"]] += 1
            det["total_bytes"] += e["bytes"]
            if e.get("response_time") is not None:
                det["rt_values"].append(e["response_time"])
            if e["timestamp"] > det["last_seen"]:
                det["last_seen"] = e["timestamp"]
            if e["timestamp"] < det["first_seen"]:
                det["first_seen"] = e["timestamp"]

        ip_table = []
        for ip, det in ip_details.items():
            s = _stats(det["rt_values"])
            ip_table.append({
                "ip": ip, "total": det["total"],
                "first_seen": det["first_seen"], "last_seen": det["last_seen"],
                "total_bytes": det["total_bytes"],
                "avg_rt": s["avg"], "min_rt": s["min"], "max_rt": s["max"],
                "p95_rt": s["p95"],
                "status_codes": dict(det["statuses"].most_common()),
            })
        ip_table.sort(key=lambda x: x["total"], reverse=True)

        status_table = [{"code": str(k), "count": v, "pct": round(v / parsed * 100, 2)}
                        for k, v in status_counter.most_common()]

        rt_scatter = []
        step = max(1, len(entries) // 500)
        for i in range(0, len(entries), step):
            e = entries[i]
            if e.get("response_time") is not None:
                rt_scatter.append({
                    "t": e["timestamp"],
                    "rt": round(e["response_time"], 3),
                    "path": e["path"],
                    "status": e["status"],
                })

        hourly_perf = []
        for h in sorted(hourly.keys()):
            vals = hourly_rt.get(h, [])
            s = _stats(vals)
            hourly_perf.append({
                "hour": h,
                "requests": hourly[h],
                "avg_rt": s["avg"],
                "p95_rt": s["p95"],
                "max_rt": s["max"],
                "status": "critical" if (s["max"] or 0) > CRITICAL_THRESHOLD else
                          "degraded" if (s["avg"] or 0) > SLOW_THRESHOLD else "healthy",
            })

        incidents = _detect_incidents(hourly_rt)

        p95_all = _percentile(sorted(rt_values), 0.95) or 0
        max_all = max(rt_values) if rt_values else 0
        if max_all > CRITICAL_THRESHOLD:
            health = "critical"
        elif p95_all > SLOW_THRESHOLD or max_all > SLOW_THRESHOLD:
            health = "degraded"
        else:
            health = "healthy"

        return {
            "log_type": "nginx_access",
            "log_type_label": "Nginx Access Log",
            "total_lines": total,
            "parsed": parsed,
            "parse_errors": self.errors,
            "processing_ms": self.processing_ms,
            "time_range": {"start": self.start_time, "end": self.end_time},
            "summary": {
                "total_requests": parsed,
                "unique_ips": len(ip_counter),
                "unique_paths": len(path_counter),
                "total_bytes": total_bytes,
                "total_bytes_human": _human_bytes(total_bytes),
                "error_rate": round(error_count / parsed * 100, 2) if parsed else 0,
                "health": health,
                "incident_count": len(incidents),
                **_stats(rt_values),
            },
            "upstream_timing": {
                "rt": _stats(rt_values),
                "urt": _stats(urt_values),
                "uht": _stats(uht_values),
                "uct": _stats(uct_values),
            },
            "charts": {
                "status_distribution": [{"label": str(k), "value": v} for k, v in status_counter.most_common()],
                "hourly_timeline": [{"label": h, "value": c} for h, c in sorted(hourly.items())],
                "method_distribution": [{"label": k, "value": v} for k, v in method_counter.most_common()],
                "top_endpoints": [{"label": p, "value": c} for p, c in path_counter.most_common(15)],
                "top_ips": [{"label": ip, "value": c} for ip, c in ip_counter.most_common(10)],
                "response_time_histogram": _histogram(rt_values, "Response Time (s)"),
                "bytes_distribution": _histogram([e["bytes"] for e in entries], "Bytes"),
                "rt_scatter": rt_scatter,
                "endpoint_rt": [
                    {"label": e["path"], "avg": e["rt"]["avg"], "p95": e["rt"]["p95"], "max": e["rt"]["max"], "count": e["count"]}
                    for e in endpoint_table[:10]
                ],
            },
            "tables": {
                "ip_details": ip_table,
                "status_codes": status_table,
                "top_endpoints": [
                    {"path": p, "count": c, "pct": round(c / parsed * 100, 2)}
                    for p, c in path_counter.most_common(20)
                ],
                "endpoint_performance": endpoint_table[:15],
                "hourly_performance": hourly_perf,
                "incidents": incidents,
            },
        }


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"


def _histogram(values: list, label: str) -> list:
    if not values:
        return []
    n = min(len(values), 20)
    step = max(1, len(values) // n)
    buckets = []
    sorted_vals = sorted(values)
    for i in range(0, len(sorted_vals), step):
        bucket_end = min(i + step, len(sorted_vals))
        bucket_val = sorted_vals[bucket_end - 1]
        buckets.append({"label": f"≤{round(bucket_val, 2)}", "value": bucket_end - i})
    return buckets
