import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analyzers.report import detect_log_type, parse_and_analyze


NGINX_ACCESS_SAMPLE = '\n'.join([
    '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET /api/users HTTP/1.1" 200 1234',
    '10.0.0.2 - - [18/Jul/2025:10:00:01 +0500] "POST /api/orders HTTP/1.1" 201 567',
    '10.0.0.3 - - [18/Jul/2025:10:00:02 +0500] "GET / HTTP/1.1" 200 890',
])

NGINX_ERROR_SAMPLE = '\n'.join([
    '2025/07/18 14:30:00 [error] 1234#5678: something failed',
    '2025/07/18 14:30:01 [warn] 1234#5678: something warning',
    '2025/07/18 14:30:02 [error] 1234#5678: another error',
])

CONTAINER_SAMPLE = '\n'.join([
    '2025-07-18T14:30:00.123456Z stdout F App started',
    '2025-07-18T14:30:01.654321Z stderr F Error occurred',
    '2025-07-18T14:30:02.000000Z stdout A Processing request',
])

SYSLOG_SAMPLE = '\n'.join([
    'Jul 18 14:30:00 myhost sshd[1234]: Failed password for root from 10.0.0.1',
    'Jul 18 14:30:01 myhost kernel: something',
    'Jul 18 14:30:02 myhost sshd[1234]: Failed password for user admin from 10.0.0.2',
])

API_BACKEND_SAMPLE = '\n'.join([
    '{"timestamp":"2025-07-18T14:30:00Z","level":"info","message":"started"}',
    '{"timestamp":"2025-07-18T14:30:01Z","level":"error","message":"failed"}',
    '{"timestamp":"2025-07-18T14:30:02Z","level":"info","message":"done"}',
])

POSTGRES_SAMPLE = '\n'.join([
    '2025-07-18 14:30:00.123 UTC [1234] LOG:  database system is ready',
    '2025-07-18 14:30:01.456 UTC [1234] LOG:  duration: 10.000 ms  statement: SELECT 1',
    '2025-07-18 14:30:02.789 UTC [1234] ERROR:  something failed',
])


def test_detect_nginx_access():
    typ, conf, scores = detect_log_type(NGINX_ACCESS_SAMPLE)
    assert typ == "nginx_access"
    assert conf > 0


def test_detect_nginx_error():
    typ, conf, scores = detect_log_type(NGINX_ERROR_SAMPLE)
    assert typ == "nginx_error"
    assert conf > 0


def test_detect_container():
    typ, conf, scores = detect_log_type(CONTAINER_SAMPLE)
    assert typ == "container"
    assert conf > 0


def test_detect_syslog():
    typ, conf, scores = detect_log_type(SYSLOG_SAMPLE)
    assert typ == "syslog"
    assert conf > 0


def test_detect_api_backend():
    typ, conf, scores = detect_log_type(API_BACKEND_SAMPLE)
    assert typ == "api_backend"
    assert conf > 0


def test_detect_postgres():
    typ, conf, scores = detect_log_type(POSTGRES_SAMPLE)
    assert typ == "postgres"
    assert conf > 0


def test_detect_unknown():
    typ, conf, scores = detect_log_type("random text\nanother random line\nmore random")
    assert typ is None
    assert conf == 0.0


def test_detect_too_few_matches():
    raw = "10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] \"GET / HTTP/1.1\" 200 100\nrandom line"
    typ, conf, scores = detect_log_type(raw)
    assert typ is None


def test_parse_and_analyze_auto():
    report = parse_and_analyze(NGINX_ACCESS_SAMPLE, log_type="auto")
    assert report.get("log_type") == "nginx_access"
    assert "detection_confidence" in report


def test_parse_and_analyze_explicit():
    report = parse_and_analyze(NGINX_ACCESS_SAMPLE, log_type="nginx_access")
    assert report["log_type"] == "nginx_access"
    assert report["parsed"] > 0


def test_parse_and_analyze_unknown_type():
    result = parse_and_analyze("data", log_type="unknown_type")
    assert "error" in result


def test_parse_and_analyze_unrecognized():
    result = parse_and_analyze("random text\nmore random\neven more", log_type=None)
    assert "error" in result


def test_parse_and_analyze_return_parser():
    report, parser = parse_and_analyze(NGINX_ACCESS_SAMPLE, log_type="nginx_access", return_parser=True)
    assert report["log_type"] == "nginx_access"
    assert parser is not None


def test_parse_and_analyze_exclude_ips():
    report = parse_and_analyze(NGINX_ACCESS_SAMPLE, log_type="nginx_access", exclude_ips=["10.0.0.1"])
    assert report["parsed"] == 2
    assert "excluded_ips" in report


def test_parse_and_analyze_exception_handling():
    result = parse_and_analyze("not a valid log at all\nanother line\nmore lines\nextra\nmore\nenough")
    assert "error" in result or result.get("log_type") is None


def test_parse_and_analyze_all_types():
    for sample, log_type in [
        (NGINX_ACCESS_SAMPLE, "nginx_access"),
        (NGINX_ERROR_SAMPLE, "nginx_error"),
        (CONTAINER_SAMPLE, "container"),
        (SYSLOG_SAMPLE, "syslog"),
        (API_BACKEND_SAMPLE, "api_backend"),
        (POSTGRES_SAMPLE, "postgres"),
        (CSV_SAMPLE, "csv"),
    ]:
        report = parse_and_analyze(sample, log_type=log_type)
        assert report.get("log_type") == log_type


def test_parse_and_analyze_auto_confidence():
    report = parse_and_analyze(NGINX_ACCESS_SAMPLE, log_type="auto")
    assert "detection_confidence" in report
    assert "detection_scores" in report
    assert report["detection_confidence"] > 0


def test_parse_and_analyze_none_type():
    report = parse_and_analyze(NGINX_ACCESS_SAMPLE, log_type=None)
    assert report.get("log_type") == "nginx_access"


CSV_SAMPLE = '\n'.join([
    'timestamp,level,endpoint,status,duration',
    '2025-07-18 10:00:00,INFO,/api/v1,200,150',
    '2025-07-18 10:00:01,ERROR,/api/v2,500,2300',
    '2025-07-18 10:00:02,INFO,/api/v1,200,90',
])

CSV_NO_HEADER_MATCH = '\n'.join([
    'just some random text',
    'another random line',
    'more random stuff',
])


def test_detect_csv():
    typ, conf, scores = detect_log_type(CSV_SAMPLE)
    assert typ == "csv"
    assert conf > 0


def test_detect_csv_not_false_positive():
    typ, conf, scores = detect_log_type(CSV_NO_HEADER_MATCH)
    assert typ is None


def test_detect_csv_not_on_nginx():
    typ, conf, scores = detect_log_type(NGINX_ACCESS_SAMPLE)
    assert typ != "csv"


def test_detect_csv_not_on_syslog():
    typ, conf, scores = detect_log_type(SYSLOG_SAMPLE)
    assert typ != "csv"


def test_parse_and_analyze_csv_auto():
    report = parse_and_analyze(CSV_SAMPLE, log_type="auto")
    assert report.get("log_type") == "csv"
    assert "detection_confidence" in report


def test_parse_and_analyze_csv_explicit():
    report = parse_and_analyze(CSV_SAMPLE, log_type="csv")
    assert report["log_type"] == "csv"
    assert report["parsed"] == 3


def test_parse_and_analyze_all_types_includes_csv():
    for sample, log_type in [
        (NGINX_ACCESS_SAMPLE, "nginx_access"),
        (NGINX_ERROR_SAMPLE, "nginx_error"),
        (CONTAINER_SAMPLE, "container"),
        (SYSLOG_SAMPLE, "syslog"),
        (API_BACKEND_SAMPLE, "api_backend"),
        (POSTGRES_SAMPLE, "postgres"),
        (CSV_SAMPLE, "csv"),
    ]:
        report = parse_and_analyze(sample, log_type=log_type)
        assert report.get("log_type") == log_type
