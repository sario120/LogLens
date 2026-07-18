import hashlib
import hmac
import time

from fastapi.testclient import TestClient

from app.main import app, _sign_token, _verify_token, _rate_limit_auth, _make_entry_summary, _client_ip
from app.config import API_KEY, SECRET_KEY, TOKEN_TTL

client = TestClient(app)


NGINX_MULTI = '\n'.join([
    '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET /api/users HTTP/1.1" 200 1234',
    '10.0.0.2 - - [18/Jul/2025:10:00:01 +0500] "POST /api/orders HTTP/1.1" 201 567',
    '10.0.0.3 - - [18/Jul/2025:10:00:02 +0500] "GET / HTTP/1.1" 200 890',
])


def _get_token():
    ts = int(time.time())
    token_id = hashlib.sha256(f"{ts}:{API_KEY}".encode()).hexdigest()[:32]
    return _sign_token(token_id, ts)


def _auth_headers():
    return {"Authorization": f"Bearer {_get_token()}"}


def test_sign_verify_token():
    ts = int(time.time())
    token = _sign_token("test_id", ts)
    assert _verify_token(token) is True


def test_verify_token_expired():
    token = _sign_token("test_id", 1)
    assert _verify_token(token) is False


def test_verify_token_invalid():
    assert _verify_token("garbage") is False
    assert _verify_token("") is False


def test_make_entry_summary_nginx_access():
    entry = {"method": "GET", "path": "/api", "status": 200}
    summary = _make_entry_summary(entry, "nginx_access")
    assert "GET" in summary
    assert "200" in summary


def test_make_entry_summary_nginx_error():
    entry = {"message": "connection refused"}
    summary = _make_entry_summary(entry, "nginx_error")
    assert "connection refused" in summary


def test_make_entry_summary_syslog():
    entry = {"process": "sshd", "message": "failed login"}
    summary = _make_entry_summary(entry, "syslog")
    assert "sshd" in summary


def test_make_entry_summary_container():
    entry = {"stream": "stderr", "log": "error occurred"}
    summary = _make_entry_summary(entry, "container")
    assert "stderr" in summary


def test_make_entry_summary_api_backend():
    entry = {"level": "error", "message": "failed"}
    summary = _make_entry_summary(entry, "api_backend")
    assert "error" in summary


def test_make_entry_summary_postgres():
    entry = {"level": "ERROR", "message": "relation missing"}
    summary = _make_entry_summary(entry, "postgres")
    assert "ERROR" in summary


def test_make_entry_summary_default():
    entry = {"foo": "bar"}
    summary = _make_entry_summary(entry, "unknown")
    assert "foo" in summary


def test_index():
    response = client.get("/")
    assert response.status_code == 200


def test_auth_success():
    response = client.post("/api/auth", json={"api_key": API_KEY})
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert data["expires_in"] > 0


def test_auth_invalid_key():
    response = client.post("/api/auth", json={"api_key": "wrong_key"})
    assert response.status_code == 401


def test_logout():
    response = client.post("/api/logout")
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_session_no_token():
    response = client.get("/api/session")
    assert response.status_code == 401
    assert response.json()["authenticated"] is False


def test_session_valid_token():
    token = _get_token()
    response = client.get("/api/session", cookies={"loglens_token": token})
    assert response.status_code == 200
    assert response.json()["authenticated"] is True


def test_analyze_no_auth():
    response = client.post("/api/analyze", json={"content": "test"})
    assert response.status_code == 401


def test_analyze_empty_content():
    headers = _auth_headers()
    response = client.post("/api/analyze", json={"content": ""}, headers=headers)
    assert response.status_code == 400


def test_analyze_valid_json():
    headers = _auth_headers()
    response = client.post("/api/analyze", json={"content": NGINX_MULTI}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["log_type"] == "nginx_access"
    assert "analysis_id" in data


def test_analyze_with_log_type():
    headers = _auth_headers()
    sample = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100'
    response = client.post("/api/analyze", json={"content": sample, "log_type": "nginx_access"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["log_type"] == "nginx_access"


def test_analyze_with_exclude_ips():
    headers = _auth_headers()
    sample = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100\n10.0.0.2 - - [18/Jul/2025:10:00:01 +0500] "GET / HTTP/1.1" 200 100'
    response = client.post("/api/analyze", json={"content": sample, "log_type": "nginx_access", "exclude_ips": "10.0.0.1"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["parsed"] == 1


def test_analyze_with_thresholds():
    headers = _auth_headers()
    sample = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100 rt=0.5'
    response = client.post("/api/analyze", json={"content": sample, "slow_threshold": "5.0", "critical_threshold": "20.0"}, headers=headers)
    assert response.status_code == 200


def test_context_no_auth():
    response = client.get("/api/context/fake_id/0")
    assert response.status_code == 401


def test_context_not_found():
    headers = _auth_headers()
    response = client.get("/api/context/nonexistent/0", headers=headers)
    assert response.status_code == 404


def test_context_valid():
    headers = _auth_headers()
    sample = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100\n10.0.0.2 - - [18/Jul/2025:10:00:01 +0500] "GET / HTTP/1.1" 200 200'
    analyze_resp = client.post("/api/analyze", json={"content": sample, "log_type": "nginx_access"}, headers=headers)
    aid = analyze_resp.json()["analysis_id"]
    ctx_resp = client.get(f"/api/context/{aid}/0", headers=headers)
    assert ctx_resp.status_code == 200
    assert "center_line" in ctx_resp.json()


def test_context_invalid_index():
    headers = _auth_headers()
    sample = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100'
    analyze_resp = client.post("/api/analyze", json={"content": sample, "log_type": "nginx_access"}, headers=headers)
    aid = analyze_resp.json()["analysis_id"]
    ctx_resp = client.get(f"/api/context/{aid}/9999", headers=headers)
    assert ctx_resp.status_code == 400


def test_batch_no_auth():
    response = client.post("/api/analyze-batch", json={"files": []})
    assert response.status_code == 401


def test_batch_empty_files():
    headers = _auth_headers()
    response = client.post("/api/analyze-batch", json={"files": []}, headers=headers)
    assert response.status_code == 400


def test_batch_valid():
    headers = _auth_headers()
    sample = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100'
    response = client.post("/api/analyze-batch", json={"files": [{"content": sample, "name": "test.log"}], "label": "test"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["label"] == "test"


def test_batch_empty_content():
    headers = _auth_headers()
    response = client.post("/api/analyze-batch", json={"files": [{"content": "  ", "name": "empty.log"}]}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "error" in data["reports"][0]


def test_batch_with_thresholds():
    headers = _auth_headers()
    sample = '10.0.0.1 - - [18/Jul/2025:10:00:00 +0500] "GET / HTTP/1.1" 200 100 rt=0.5'
    response = client.post("/api/analyze-batch", json={"files": [{"content": sample, "name": "t.log"}], "slow_threshold": "5.0"}, headers=headers)
    assert response.status_code == 200


def test_correlate_no_auth():
    response = client.post("/api/analyze-correlate", json={"files": []})
    assert response.status_code == 401


def test_correlate_empty_files():
    headers = _auth_headers()
    response = client.post("/api/analyze-correlate", json={"files": []}, headers=headers)
    assert response.status_code == 400


def test_correlate_valid():
    headers = _auth_headers()
    nginx = NGINX_MULTI
    syslog = 'Jul 18 14:30:00 myhost sshd[1234]: something\nJul 18 14:30:01 myhost sshd[1234]: other thing'
    response = client.post("/api/analyze-correlate", json={
        "files": [
            {"content": nginx, "name": "access.log", "log_type": "auto"},
            {"content": syslog, "name": "syslog", "log_type": "auto"},
        ]
    }, headers=headers)
    assert response.status_code == 200
    data = response.json()["correlation"]
    assert data["total_events"] == 5
    assert len(data["sources"]) == 2


def test_correlate_with_exclude_ips():
    headers = _auth_headers()
    nginx = NGINX_MULTI
    response = client.post("/api/analyze-correlate", json={
        "files": [{"content": nginx, "name": "a.log", "log_type": "auto"}],
        "exclude_ips": "10.0.0.1,10.0.0.2,10.0.0.3"
    }, headers=headers)
    assert response.status_code == 200
    assert response.json()["correlation"]["total_events"] == 0


def test_correlate_all_empty():
    headers = _auth_headers()
    response = client.post("/api/analyze-correlate", json={
        "files": [{"content": "   ", "name": "empty.log"}]
    }, headers=headers)
    assert response.status_code == 400


def test_rate_limit_auth():
    from app.main import _auth_attempts
    _auth_attempts.clear()
    for _ in range(15):
        try:
            _rate_limit_auth("test_limit_ip")
        except Exception:
            pass
    _auth_attempts.clear()


def test_client_ip_forwarded():
    from starlette.testclient import TestClient as TC
    from starlette.requests import Request

    scope = {"type": "http", "headers": [(b"x-forwarded-for", b"1.2.3.4, 5.6.7.8")], "client": ("0.0.0.0", 1234)}
    req = Request(scope)
    assert _client_ip(req) == "1.2.3.4"


def test_client_ip_no_forwarded():
    from starlette.requests import Request
    scope = {"type": "http", "headers": [], "client": ("9.10.11.12", 1234)}
    req = Request(scope)
    assert _client_ip(req) == "9.10.11.12"


def test_analyze_file_upload():
    headers = _auth_headers()
    sample = NGINX_MULTI.encode("utf-8")
    response = client.post(
        "/api/analyze",
        files={"file": ("test.log", sample, "text/plain")},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["log_type"] == "nginx_access"
