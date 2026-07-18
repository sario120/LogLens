from app.parsers.base import BaseParser, MONTH_MAP
from app.parsers.nginx_access import NginxAccessParser


def test_month_map_completeness():
    assert len(MONTH_MAP) == 12
    assert MONTH_MAP["Jan"] == 1
    assert MONTH_MAP["Dec"] == 12


def test_hour_key_iso():
    assert BaseParser._hour_key("2025-07-18T14:30:00") == "2025-07-18 14:00"
    assert BaseParser._hour_key("2025-07-18T09:05:12.345") == "2025-07-18 09:00"


def test_hour_key_space_delimited():
    assert BaseParser._hour_key("Jul 18 14:30:00") == "14:00"


def test_hour_key_empty():
    assert BaseParser._hour_key("") == "unknown"
    assert BaseParser._hour_key(None) == "unknown"


def test_hour_key_short_parts():
    assert BaseParser._hour_key("2025-07-18 9:00") == "9::00"


def test_get_ip_fallback_keys():
    parser = NginxAccessParser()
    assert parser._get_ip({"ip": "1.2.3.4"}) == "1.2.3.4"
    assert parser._get_ip({"source_ip": "5.6.7.8"}) == "5.6.7.8"
    assert parser._get_ip({"client": "9.10.11.12"}) == "9.10.11.12"
    assert parser._get_ip({}) is None


def test_get_context_invalid_index():
    parser = NginxAccessParser()
    parser.parse("1.2.3.4 - - [18/Jul/2025:14:30:00 +0500] \"GET / HTTP/1.1\" 200 1234")
    result = parser.get_context(-1)
    assert "error" in result
    result = parser.get_context(999)
    assert "error" in result


def test_get_context_valid():
    parser = NginxAccessParser()
    raw = "line0\nline1\nline2\nline3\nline4"
    parser.parse(raw)
    if parser.entries:
        ctx = parser.get_context(0, before=1, after=1)
        assert "center_line" in ctx
        assert "context" in ctx
        assert len(ctx["context"]) > 0


def test_compute_time_range():
    parser = NginxAccessParser()
    raw = (
        '1.2.3.4 - - [18/Jul/2025:10:00:00 +0500] "GET /a HTTP/1.1" 200 100\n'
        '1.2.3.4 - - [18/Jul/2025:12:00:00 +0500] "GET /b HTTP/1.1" 200 200'
    )
    report = parser.parse(raw)
    assert report["time_range"]["start"] is not None
    assert report["time_range"]["end"] is not None


def test_exclude_ips():
    raw = (
        '1.2.3.4 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100\n'
        '5.6.7.8 - - [18/Jul/2025:10:01:00 +0500] "GET / HTTP/1.1" 200 100'
    )
    parser = NginxAccessParser()
    report = parser.parse(raw, exclude_ips=["1.2.3.4"])
    assert report["parsed"] == 1
    assert report["_entries"][0]["ip"] == "5.6.7.8"


def test_empty_input():
    parser = NginxAccessParser()
    report = parser.parse("")
    assert report["parsed"] == 0
    assert report["parse_errors"] == 0


def test_whitespace_only():
    parser = NginxAccessParser()
    report = parser.parse("   \n  \n  ")
    assert report["parsed"] == 0
