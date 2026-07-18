import json
from app.parsers.api_backend import ApiBackendParser, _safe_int, _safe_float, LEVEL_MAP

JSON_LOG = '{"timestamp":"2025-07-18T14:30:00Z","level":"info","method":"GET","path":"/api/users","status":200,"duration":0.123,"message":"request processed","request_id":"abc-123"}'
JSON_LOG_ALT_FIELDS = '{"time":"2025-07-18T14:30:00Z","severity":"error","http_method":"POST","url":"/api/orders","status":500,"duration":1.5,"msg":"internal error"}'
JSON_LOG_EXTRA = '{"timestamp":"2025-07-18T14:30:00Z","level":"info","message":"ok","custom_field":"custom_value","trace_id":"xyz-789"}'
TEXT_LOG = '2025-07-18T14:30:00Z [INFO] Application started on port 8080'
TEXT_LOG_BRACKET = '2025-07-18T14:30:00Z [ERROR] Connection failed'
TEXT_LOG_BARE = '2025-07-18T14:30:00Z ERROR Something went wrong'


def test_safe_int_valid():
    assert _safe_int("42") == 42
    assert _safe_int(42) == 42


def test_safe_int_none():
    assert _safe_int(None) is None


def test_safe_int_invalid():
    assert _safe_int("abc") is None


def test_safe_float_valid():
    assert _safe_float("3.14") == 3.14


def test_safe_float_none():
    assert _safe_float(None) is None


def test_safe_float_invalid():
    assert _safe_float("abc") is None


def test_level_map():
    assert LEVEL_MAP["error"] == 4
    assert LEVEL_MAP["fatal"] == 5
    assert LEVEL_MAP["warning"] == 3
    assert LEVEL_MAP["warn"] == 3


def test_parse_json_standard():
    parser = ApiBackendParser()
    entry = parser._parse_json(JSON_LOG)
    assert entry is not None
    assert entry["level"] == "info"
    assert entry["method"] == "GET"
    assert entry["path"] == "/api/users"
    assert entry["status"] == 200
    assert entry["duration"] == 0.123
    assert entry["request_id"] == "abc-123"


def test_parse_json_alt_fields():
    parser = ApiBackendParser()
    entry = parser._parse_json(JSON_LOG_ALT_FIELDS)
    assert entry["level"] == "error"
    assert entry["method"] == "POST"
    assert entry["path"] == "/api/orders"
    assert entry["status"] == 500


def test_parse_json_extra_fields():
    parser = ApiBackendParser()
    entry = parser._parse_json(JSON_LOG_EXTRA)
    assert entry["extra"]["custom_field"] == "custom_value"
    assert entry["request_id"] == "xyz-789"


def test_parse_json_invalid():
    parser = ApiBackendParser()
    assert parser._parse_json("{not json}") is None


def test_parse_text_bracket_level():
    parser = ApiBackendParser()
    entry = parser._parse_text(TEXT_LOG_BRACKET)
    assert entry is not None
    assert entry["level"] == "error"


def test_parse_text_bare_level():
    parser = ApiBackendParser()
    entry = parser._parse_text(TEXT_LOG_BARE)
    assert entry is not None
    assert entry["level"] == "error"


def test_parse_line_json():
    parser = ApiBackendParser()
    entry = parser._parse_line(JSON_LOG)
    assert entry is not None
    assert entry["method"] == "GET"


def test_parse_line_text():
    parser = ApiBackendParser()
    entry = parser._parse_line(TEXT_LOG)
    assert entry is not None
    assert entry["level"] == "info"


def test_parse_line_invalid():
    parser = ApiBackendParser()
    assert parser._parse_line("not a log line at all") is None


def test_parse_full_report_json():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    assert report["log_type"] == "api_backend"
    assert report["parsed"] == 2
    assert report["summary"]["total_entries"] == 2
    assert report["summary"]["error_count"] == 1
    assert report["summary"]["warn_count"] == 0


def test_error_rate():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    assert report["summary"]["error_rate"] == 50.0


def test_duration_stats():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    assert report["summary"]["avg_duration"] is not None
    assert report["summary"]["max_duration"] is not None


def test_endpoint_details():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    assert len(report["tables"]["endpoint_details"]) == 2


def test_level_distribution_chart():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    levels = {d["label"]: d["value"] for d in report["charts"]["level_distribution"]}
    assert "info" in levels
    assert "error" in levels


def test_method_distribution_chart():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    methods = {d["label"]: d["value"] for d in report["charts"]["method_distribution"]}
    assert "GET" in methods
    assert "POST" in methods


def test_status_distribution_chart():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    statuses = {d["label"]: d["value"] for d in report["charts"]["status_distribution"]}
    assert "200" in statuses
    assert "500" in statuses


def test_error_samples():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG_ALT_FIELDS)
    assert len(report["tables"]["error_samples"]) == 1
    assert "_entry_idx" in report["tables"]["error_samples"][0]


def test_top_errors_chart():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG_ALT_FIELDS)
    assert len(report["charts"]["top_errors"]) == 1


def test_duration_histogram():
    lines = []
    for i in range(25):
        lines.append(json.dumps({"timestamp": f"2025-07-18T10:00:{i:02d}Z", "level": "info", "duration": float(i), "message": "ok"}))
    parser = ApiBackendParser()
    report = parser.parse("\n".join(lines))
    assert len(report["charts"]["duration_histogram"]) > 0


def test_warn_count_warning():
    log = '{"timestamp":"2025-07-18T14:30:00Z","level":"warning","message":"deprecated"}'
    parser = ApiBackendParser()
    report = parser.parse(log)
    assert report["summary"]["warn_count"] == 1


def test_warn_count_warn():
    log = '{"timestamp":"2025-07-18T14:30:00Z","level":"warn","message":"deprecated"}'
    parser = ApiBackendParser()
    report = parser.parse(log)
    assert report["summary"]["warn_count"] == 1


def test_unique_endpoints():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG + "\n" + JSON_LOG_ALT_FIELDS)
    assert report["summary"]["unique_endpoints"] == 2


def test_hourly_timeline():
    parser = ApiBackendParser()
    report = parser.parse(JSON_LOG)
    assert len(report["charts"]["hourly_timeline"]) == 1
