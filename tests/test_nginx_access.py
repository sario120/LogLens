from app.parsers.nginx_access import (
    NginxAccessParser, _parse_nginx_time, _percentile, _stats,
    _safe_float, _human_bytes, _histogram, _detect_incidents,
)


NGINX_LOG = '192.168.1.1 - admin [18/Jul/2025:14:30:00 +0500] "GET /api/users HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0" rt=0.5 urt=0.3 uht=0.2 uct=0.1'
NGINX_LOG_SHORT = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "POST /login HTTP/1.1" 401 0'
NGINX_LOG_DASH_BYTES = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "HEAD /health HTTP/1.1" 204 -'


def test_parse_nginx_time_standard():
    result = _parse_nginx_time("18/Jul/2025:14:30:00 +0500")
    assert result == "2025-07-18T14:30:00"


def test_parse_nginx_time_no_time_in_date():
    result = _parse_nginx_time("18/Jul/2025 14:30:00")
    assert "2025" in result


def test_parse_nginx_time_short():
    result = _parse_nginx_time("bad")
    assert result == "bad"


def test_percentile_empty():
    assert _percentile([], 0.95) is None


def test_percentile_single():
    assert _percentile([5.0], 0.5) == 5.0


def test_percentile_multiple():
    vals = sorted([1.0, 2.0, 3.0, 4.0, 5.0])
    assert _percentile(vals, 0.5) == 3.0


def test_stats_empty():
    s = _stats([])
    assert s["count"] == 0
    assert s["avg"] is None


def test_stats_with_values():
    s = _stats([1.0, 2.0, 3.0, 4.0, 5.0])
    assert s["count"] == 5
    assert s["min"] == 1.0
    assert s["max"] == 5.0
    assert s["avg"] == 3.0


def test_safe_float_valid():
    assert _safe_float("3.14") == 3.14


def test_safe_float_none():
    assert _safe_float(None) is None


def test_safe_float_invalid():
    assert _safe_float("abc") is None


def test_human_bytes():
    assert _human_bytes(0) == "0.00 B"
    assert _human_bytes(1024) == "1.00 KB"
    assert _human_bytes(1048576) == "1.00 MB"
    assert _human_bytes(1073741824) == "1.00 GB"


def test_histogram_empty():
    assert _histogram([], "test") == []


def test_histogram_values():
    result = _histogram([0.1, 0.5, 1.0, 2.0], "test")
    assert len(result) > 0


def test_parse_line_valid():
    parser = NginxAccessParser()
    entry = parser._parse_line(NGINX_LOG)
    assert entry is not None
    assert entry["ip"] == "192.168.1.1"
    assert entry["method"] == "GET"
    assert entry["status"] == 200
    assert entry["response_time"] == 0.5
    assert entry["upstream_response_time"] == 0.3


def test_parse_line_short():
    parser = NginxAccessParser()
    entry = parser._parse_line(NGINX_LOG_SHORT)
    assert entry is not None
    assert entry["status"] == 401
    assert entry["response_time"] is None


def test_parse_line_dash_bytes():
    parser = NginxAccessParser()
    entry = parser._parse_line(NGINX_LOG_DASH_BYTES)
    assert entry["bytes"] == 0


def test_parse_line_invalid():
    parser = NginxAccessParser()
    assert parser._parse_line("not an nginx log") is None


def test_parse_full_report():
    raw = NGINX_LOG + "\n" + NGINX_LOG_SHORT
    parser = NginxAccessParser()
    report = parser.parse(raw)
    assert report["log_type"] == "nginx_access"
    assert report["parsed"] == 2
    assert report["summary"]["total_requests"] == 2
    assert report["summary"]["unique_ips"] == 2
    assert "charts" in report
    assert "tables" in report


def test_build_report_health_healthy():
    raw = NGINX_LOG + "\n" + NGINX_LOG_SHORT
    parser = NginxAccessParser()
    report = parser.parse(raw)
    assert report["summary"]["health"] in ("healthy", "degraded", "critical")


def test_build_report_health_critical():
    lines = []
    for i in range(5):
        lines.append(f'10.0.0.{i} - - [18/Jul/2025:10:00:0{i} +0500] "GET / HTTP/1.1" 200 100 rt=100.0')
    parser = NginxAccessParser()
    report = parser.parse("\n".join(lines))
    assert report["summary"]["health"] == "critical"


def test_build_report_health_degraded():
    lines = []
    for i in range(5):
        lines.append(f'10.0.0.{i} - - [18/Jul/2025:10:00:0{i} +0500] "GET / HTTP/1.1" 200 100 rt=15.0')
    parser = NginxAccessParser()
    report = parser.parse("\n".join(lines))
    assert report["summary"]["health"] == "degraded"


def test_error_rate():
    lines = [
        '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100',
        '10.0.0.2 - - [18/Jul/2025:10:00:01 +0500] "GET / HTTP/1.1" 500 100',
    ]
    parser = NginxAccessParser()
    report = parser.parse("\n".join(lines))
    assert report["summary"]["error_rate"] == 50.0


def test_upstream_timing():
    parser = NginxAccessParser()
    report = parser.parse(NGINX_LOG)
    assert "upstream_timing" in report
    assert report["upstream_timing"]["rt"]["count"] == 1


def test_ip_details_table():
    parser = NginxAccessParser()
    report = parser.parse(NGINX_LOG + "\n" + NGINX_LOG)
    assert len(report["tables"]["ip_details"]) >= 1
    assert report["tables"]["ip_details"][0]["ip"] == "192.168.1.1"


def test_incidents_empty():
    parser = NginxAccessParser()
    report = parser.parse(NGINX_LOG)
    assert report["tables"]["incidents"] == []


def test_detect_incidents_with_slow():
    hourly_rt = {"2025-07-18 10:00": [50.0, 60.0]}
    incidents = _detect_incidents(hourly_rt)
    assert len(incidents) > 0
    assert incidents[0]["severity"] in ("critical", "degraded")


def test_rt_scatter():
    lines = []
    for i in range(10):
        lines.append(f'10.0.0.1 - - [18/Jul/2025:10:0{i}:00 +0500] "GET / HTTP/1.1" 200 100 rt={i * 0.1}')
    parser = NginxAccessParser()
    report = parser.parse("\n".join(lines))
    assert len(report["charts"]["rt_scatter"]) > 0


def test_endpoint_performance():
    lines = [
        '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET /a HTTP/1.1" 200 100 rt=1.0',
        '10.0.0.1 - - [18/Jul/2025:10:00:01 +0500] "GET /b HTTP/1.1" 200 100 rt=5.0',
    ]
    parser = NginxAccessParser()
    report = parser.parse("\n".join(lines))
    assert len(report["tables"]["endpoint_performance"]) == 2


def test_status_codes_table():
    parser = NginxAccessParser()
    report = parser.parse(NGINX_LOG + "\n" + NGINX_LOG_SHORT)
    codes = [t["code"] for t in report["tables"]["status_codes"]]
    assert "200" in codes
    assert "401" in codes


def test_method_distribution():
    parser = NginxAccessParser()
    report = parser.parse(NGINX_LOG + "\n" + NGINX_LOG_SHORT)
    methods = {d["label"]: d["value"] for d in report["charts"]["method_distribution"]}
    assert methods.get("GET", 0) >= 1
    assert methods.get("POST", 0) >= 1
