from app.parsers.nginx_error import (
    NginxErrorParser, _parse_nginx_time, _extract_client,
)

NGINX_ERROR = '2025/07/18 14:30:00 [error] 1234#5678: *9012 client: 192.168.1.1, server: example.com, request: "GET / HTTP/1.1", upstream: "http://backend:8080"'
NGINX_ERROR_NO_CLIENT = '2025/07/18 14:30:00 [crit] 1234#5678: accept() failed (24: Too many open files)'
NGINX_ERROR_WITH_CONNECTION = '2025/07/18 14:30:00 [warn] 1234#5678: 10.0.0.1 closed connection'
NGINX_ERROR_DDMMYYYY = '2025/07/18 14:30:00 [error] 1234#5678: something failed'


def test_parse_nginx_time_yyyymmdd():
    result = _parse_nginx_time("2025/07/18 14:30:00")
    assert result == "2025-07-18T14:30:00"


def test_parse_nginx_time_ddmmyyyy():
    result = _parse_nginx_time("18/Jul/2025 14:30:00")
    assert result == "2025-07-18T14:30:00"


def test_parse_nginx_time_short():
    assert _parse_nginx_time("bad") == "bad"


def test_extract_client_with_keyword():
    msg = 'client: 192.168.1.1, server: example.com'
    assert _extract_client(msg) == "192.168.1.1"


def test_extract_client_ip_only():
    msg = 'connection from 10.0.0.1'
    assert _extract_client(msg) == "10.0.0.1"


def test_extract_client_none():
    assert _extract_client("no ip here") is None


def test_extract_client_strips_comma():
    msg = 'client: 10.0.0.1,'
    assert _extract_client(msg) == "10.0.0.1"


def test_parse_line_valid():
    parser = NginxErrorParser()
    entry = parser._parse_line(NGINX_ERROR)
    assert entry is not None
    assert entry["level"] == "error"
    assert entry["pid"] == 1234
    assert entry["tid"] == 5678
    assert entry["cid"] == 9012
    assert entry["client"] == "192.168.1.1"


def test_parse_line_no_client():
    parser = NginxErrorParser()
    entry = parser._parse_line(NGINX_ERROR_NO_CLIENT)
    assert entry is not None
    assert entry["client"] is None
    assert entry["level"] == "crit"


def test_parse_line_with_connection():
    parser = NginxErrorParser()
    entry = parser._parse_line(NGINX_ERROR_WITH_CONNECTION)
    assert entry["client"] == "10.0.0.1"


def test_parse_line_invalid():
    parser = NginxErrorParser()
    assert parser._parse_line("not nginx error") is None


def test_parse_full_report():
    raw = NGINX_ERROR + "\n" + NGINX_ERROR_NO_CLIENT + "\n" + NGINX_ERROR_WITH_CONNECTION
    parser = NginxErrorParser()
    report = parser.parse(raw)
    assert report["log_type"] == "nginx_error"
    assert report["parsed"] == 3
    assert report["summary"]["total_errors"] == 3
    assert report["summary"]["crit_count"] == 1
    assert report["summary"]["error_count"] == 1
    assert report["summary"]["warn_count"] == 1


def test_unique_clients():
    raw = NGINX_ERROR + "\n" + NGINX_ERROR_NO_CLIENT
    parser = NginxErrorParser()
    report = parser.parse(raw)
    assert report["summary"]["unique_clients"] == 1


def test_level_distribution():
    raw = NGINX_ERROR + "\n" + NGINX_ERROR_NO_CLIENT + "\n" + NGINX_ERROR_WITH_CONNECTION
    parser = NginxErrorParser()
    report = parser.parse(raw)
    levels = {d["label"]: d["value"] for d in report["charts"]["level_distribution"]}
    assert "error" in levels
    assert "crit" in levels
    assert "warn" in levels


def test_level_table_sorted_by_severity():
    raw = NGINX_ERROR + "\n" + NGINX_ERROR_NO_CLIENT + "\n" + NGINX_ERROR_WITH_CONNECTION
    parser = NginxErrorParser()
    report = parser.parse(raw)
    severities = [t["severity"] for t in report["tables"]["levels"]]
    assert severities == sorted(severities)


def test_message_fingerprints():
    raw = (
        '2025/07/18 14:30:00 [error] 1234#5678: connection to 10.0.0.1 failed\n'
        '2025/07/18 14:30:01 [error] 1234#5678: connection to 10.0.0.2 failed'
    )
    parser = NginxErrorParser()
    report = parser.parse(raw)
    assert len(report["tables"]["top_messages"]) >= 1


def test_hourly_timeline():
    parser = NginxErrorParser()
    report = parser.parse(NGINX_ERROR)
    assert len(report["charts"]["hourly_timeline"]) == 1
    assert report["charts"]["hourly_timeline"][0]["value"] == 1


def test_ddmmmyyyy_timestamp():
    parser = NginxErrorParser()
    entry = parser._parse_line(NGINX_ERROR_DDMMYYYY)
    assert entry is not None
    assert "2025" in entry["timestamp"]


def test_error_report_charts():
    parser = NginxErrorParser()
    report = parser.parse(NGINX_ERROR)
    assert "top_clients" in report["charts"]
    assert "top_messages" in report["charts"]
