from app.parsers.container import ContainerLogParser, _detect_level

DOCKER_LOG = '2025-07-18T14:30:00.123456Z stdout F Application started on port 8080'
DOCKER_LOG_STDERR = '2025-07-18T14:30:01.654321Z stderr F FATAL: connection refused'
DOCKER_LOG_WITH_FLAG = '2025-07-18T14:30:02.000000Z stdout A GET /api/health 200 0.003s'
FALLBACK_LOG = '2025-07-18 15:30:00 [INFO] Server started on port 3000'


def test_detect_level_fatal():
    assert _detect_level("FATAL error occurred") == "FATAL"
    assert _detect_level("PANIC: runtime error") == "FATAL"


def test_detect_level_error():
    assert _detect_level("ERROR: connection failed") == "ERROR"
    assert _detect_level("ERR something broke") == "ERROR"


def test_detect_level_warn():
    assert _detect_level("WARNING: disk space low") == "WARN"
    assert _detect_level("WARN: deprecated call") == "WARN"


def test_detect_level_info():
    assert _detect_level("INFO: request processed") == "INFO"


def test_detect_level_debug():
    assert _detect_level("DEBUG: query plan") == "DEBUG"
    assert _detect_level("DBG: variable value") == "DEBUG"


def test_detect_level_trace():
    assert _detect_level("function TRACE enter") == "TRACE"


def test_detect_level_unknown():
    assert _detect_level("just some text") == "UNKNOWN"


def test_parse_line_docker():
    parser = ContainerLogParser()
    entry = parser._parse_line(DOCKER_LOG)
    assert entry is not None
    assert entry["stream"] == "stdout"
    assert entry["level"] == "UNKNOWN"
    assert "Application started" in entry["message"]


def test_parse_line_docker_stderr():
    parser = ContainerLogParser()
    entry = parser._parse_line(DOCKER_LOG_STDERR)
    assert entry is not None
    assert entry["stream"] == "stderr"
    assert entry["level"] == "FATAL"


def test_parse_line_docker_with_flag():
    parser = ContainerLogParser()
    entry = parser._parse_line(DOCKER_LOG_WITH_FLAG)
    assert entry is not None
    assert entry["flag"] == "A"


def test_parse_line_docker_z_stripped():
    parser = ContainerLogParser()
    entry = parser._parse_line(DOCKER_LOG)
    assert not entry["timestamp"].endswith("Z")


def test_parse_line_fallback():
    parser = ContainerLogParser()
    entry = parser._parse_line(FALLBACK_LOG)
    assert entry is not None
    assert entry["stream"] == "stdout"
    assert entry["flag"] is None


def test_parse_line_fallback_too_short():
    parser = ContainerLogParser()
    assert parser._parse_line("short") is None


def test_parse_line_invalid():
    parser = ContainerLogParser()
    assert parser._parse_line("not a container log at all and long enough") is None


def test_parse_full_report():
    raw = DOCKER_LOG + "\n" + DOCKER_LOG_STDERR + "\n" + FALLBACK_LOG
    parser = ContainerLogParser()
    report = parser.parse(raw)
    assert report["log_type"] == "container"
    assert report["parsed"] == 3
    assert report["summary"]["total_entries"] == 3
    assert report["summary"]["stdout_count"] >= 1
    assert report["summary"]["stderr_count"] >= 1


def test_error_count():
    parser = ContainerLogParser()
    report = parser.parse(DOCKER_LOG_STDERR)
    assert report["summary"]["error_count"] == 1


def test_error_rate():
    raw = DOCKER_LOG + "\n" + DOCKER_LOG_STDERR
    parser = ContainerLogParser()
    report = parser.parse(raw)
    assert report["summary"]["error_rate"] == 50.0


def test_warn_count():
    log_warn = '2025-07-18T14:30:00.123Z stdout F WARNING: low memory'
    parser = ContainerLogParser()
    report = parser.parse(log_warn)
    assert report["summary"]["warn_count"] == 1


def test_level_distribution_chart():
    raw = DOCKER_LOG + "\n" + DOCKER_LOG_STDERR
    parser = ContainerLogParser()
    report = parser.parse(raw)
    levels = {d["label"]: d["value"] for d in report["charts"]["level_distribution"]}
    assert "UNKNOWN" in levels
    assert "FATAL" in levels


def test_stream_distribution():
    raw = DOCKER_LOG + "\n" + DOCKER_LOG_STDERR
    parser = ContainerLogParser()
    report = parser.parse(raw)
    streams = {d["label"]: d["value"] for d in report["charts"]["stream_distribution"]}
    assert "stdout" in streams
    assert "stderr" in streams


def test_error_samples():
    parser = ContainerLogParser()
    report = parser.parse(DOCKER_LOG_STDERR)
    assert len(report["tables"]["error_samples"]) == 1
    assert "_entry_idx" in report["tables"]["error_samples"][0]


def test_error_fingerprints():
    raw = (
        '2025-07-18T14:30:00.000Z stderr F ERROR: timeout connecting to db host abc123\n'
        '2025-07-18T14:30:01.000Z stderr F ERROR: timeout connecting to db host def456'
    )
    parser = ContainerLogParser()
    report = parser.parse(raw)
    assert len(report["charts"]["top_errors"]) >= 1


def test_hourly_timeline():
    parser = ContainerLogParser()
    report = parser.parse(DOCKER_LOG)
    assert len(report["charts"]["hourly_timeline"]) == 1
