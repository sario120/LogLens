from app.parsers.syslog import SyslogParser, SEVERITY_MAP

BSD_LOG = 'Jul 18 14:30:00 myhost sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2'
RSYSLOG_LOG = '2025-07-18T14:30:00.123+05:00 myhost sshd[5678]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2'
NON_AUTH_LOG = 'Jul 18 14:30:00 myhost cron[9999]: CMD (/usr/bin/apt-get update)'
AUTH_FAILURE = 'Jul 18 14:30:00 myhost auth[1111]: authentication failure for user test from 5.6.7.8'


def test_severity_map():
    assert SEVERITY_MAP["auth"] == "critical"
    assert SEVERITY_MAP["sshd"] == "high"


def test_parse_line_bsd():
    parser = SyslogParser()
    entry = parser._parse_line(BSD_LOG)
    assert entry is not None
    assert entry["hostname"] == "myhost"
    assert entry["process"] == "sshd"
    assert entry["pid"] == 1234
    assert entry["is_auth_failure"] is True
    assert entry["source_ip"] == "192.168.1.100"
    assert entry["user"] == "192.168.1.100"


def test_parse_line_rsyslog():
    parser = SyslogParser()
    entry = parser._parse_line(RSYSLOG_LOG)
    assert entry is not None
    assert entry["timestamp"].startswith("2025-07-18")
    assert entry["is_auth_failure"] is True
    assert entry["source_ip"] == "10.0.0.1"


def test_parse_line_non_auth():
    parser = SyslogParser()
    entry = parser._parse_line(NON_AUTH_LOG)
    assert entry is not None
    assert entry["is_auth_failure"] is False
    assert entry["process"] == "cron"
    assert entry["pid"] == 9999
    assert entry["source_ip"] is None


def test_parse_line_auth_failure():
    parser = SyslogParser()
    entry = parser._parse_line(AUTH_FAILURE)
    assert entry is not None
    assert entry["is_auth_failure"] is True
    assert entry["source_ip"] == "5.6.7.8"
    assert entry["user"] == "test"


def test_parse_line_invalid():
    parser = SyslogParser()
    assert parser._parse_line("not a syslog line") is None


def test_parse_line_no_pid():
    log = 'Jul 18 14:30:00 myhost kernel: something happened'
    parser = SyslogParser()
    entry = parser._parse_line(log)
    assert entry is not None
    assert entry["pid"] is None


def test_auth_fail_patterns():
    patterns_to_test = [
        'Failed password for user',
        'authentication failure for user',
        'invalid user admin',
        'connection closed by preauth',
        'not valid user',
        'refused connect',
        'failed to authenticate',
        'unauthorized access',
    ]
    for msg in patterns_to_test:
        log = f'Jul 18 14:30:00 myhost sshd[1234]: {msg}'
        parser = SyslogParser()
        entry = parser._parse_line(log)
        assert entry["is_auth_failure"] is True, f"Failed for: {msg}"


def test_parse_full_report_bsd():
    parser = SyslogParser()
    report = parser.parse(BSD_LOG)
    assert report["log_type"] == "syslog"
    assert report["parsed"] == 1
    assert report["summary"]["auth_failures"] == 1
    assert report["summary"]["unique_source_ips"] == 1
    assert report["summary"]["unique_users_targeted"] == 1


def test_parse_full_report_mixed():
    raw = BSD_LOG + "\n" + RSYSLOG_LOG + "\n" + NON_AUTH_LOG + "\n" + AUTH_FAILURE
    parser = SyslogParser()
    report = parser.parse(raw)
    assert report["parsed"] == 4
    assert report["summary"]["auth_failures"] == 3
    assert report["summary"]["unique_processes"] >= 2


def test_auth_failure_rate():
    raw = BSD_LOG + "\n" + NON_AUTH_LOG
    parser = SyslogParser()
    report = parser.parse(raw)
    assert report["summary"]["auth_failure_rate"] == 50.0


def test_process_distribution():
    raw = BSD_LOG + "\n" + NON_AUTH_LOG
    parser = SyslogParser()
    report = parser.parse(raw)
    procs = {d["label"]: d["value"] for d in report["charts"]["process_distribution"]}
    assert "sshd" in procs
    assert "cron" in procs


def test_top_source_ips():
    parser = SyslogParser()
    report = parser.parse(BSD_LOG)
    assert len(report["charts"]["top_source_ips"]) == 1
    assert report["charts"]["top_source_ips"][0]["label"] == "192.168.1.100"


def test_auth_failures_detail():
    parser = SyslogParser()
    report = parser.parse(BSD_LOG)
    assert len(report["tables"]["auth_failures_detail"]) == 1
    detail = report["tables"]["auth_failures_detail"][0]
    assert "_entry_idx" in detail
    assert detail["source_ip"] == "192.168.1.100"


def test_auth_fail_messages_chart():
    raw = BSD_LOG + "\n" + RSYSLOG_LOG
    parser = SyslogParser()
    report = parser.parse(raw)
    assert len(report["charts"]["auth_fail_messages"]) >= 1


def test_hourly_timeline():
    parser = SyslogParser()
    report = parser.parse(BSD_LOG)
    assert len(report["charts"]["hourly_timeline"]) == 1
    assert report["charts"]["hourly_timeline"][0]["value"] == 1


def test_process_table():
    parser = SyslogParser()
    report = parser.parse(BSD_LOG + "\n" + NON_AUTH_LOG)
    assert len(report["tables"]["processes"]) == 2
    for t in report["tables"]["processes"]:
        assert "pct" in t


def test_user_extraction():
    log = 'Jul 18 14:30:00 myhost sshd[1234]: Failed password for user admin from 10.0.0.1'
    parser = SyslogParser()
    entry = parser._parse_line(log)
    assert entry["user"] == "admin"


def test_top_targeted_users():
    parser = SyslogParser()
    report = parser.parse(BSD_LOG)
    assert len(report["charts"]["top_targeted_users"]) >= 1
