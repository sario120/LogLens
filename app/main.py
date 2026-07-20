import hashlib
import hmac
import json
import time
import uuid
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import (
    API_KEY, SECRET_KEY, TOKEN_TTL, MAX_UPLOAD_BYTES, UPLOAD_CHUNK_SIZE,
    AUTH_MAX_ATTEMPTS, AUTH_WINDOW_SECONDS, SLOW_THRESHOLD, CRITICAL_THRESHOLD,
)
from app.analyzers.report import parse_and_analyze
from app.version import __version__

app = FastAPI(title="LogLens", version=__version__, docs_url=None, redoc_url=None)

BASE = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))

# --- analysis context cache (5 min TTL) ---
_analysis_cache: dict[str, dict] = {}  # id -> {"parser": BaseParser, "report": dict, "ts": float}
_CACHE_TTL = 300  # 5 minutes
_CACHE_CLEANUP_INTERVAL = 60
_last_cache_cleanup: float = time.time()

# --- analysis context cache ---
def _cleanup_analysis_cache():
    global _last_cache_cleanup
    now = time.time()
    if now - _last_cache_cleanup < _CACHE_CLEANUP_INTERVAL:
        return
    _last_cache_cleanup = now
    expired = [aid for aid, entry in _analysis_cache.items() if now - entry["ts"] > _CACHE_TTL]
    for aid in expired:
        del _analysis_cache[aid]


def _cache_analysis(parser, report: dict) -> str:
    _cleanup_analysis_cache()
    analysis_id = uuid.uuid4().hex[:16]
    _analysis_cache[analysis_id] = {"parser": parser, "report": report, "ts": time.time()}
    return analysis_id


# --- rate limiter: per-IP, sliding window ---
_auth_attempts: dict[str, list[float]] = defaultdict(list)
_last_cleanup: float = time.time()
_CLEANUP_INTERVAL = 60

_AUTH_RATE_LIMIT = 10
_AUTH_RATE_WINDOW = 60


def _cleanup_rate_limiters():
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < _CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    stale = [ip for ip, ts_list in _auth_attempts.items()
             if not ts_list or now - ts_list[-1] > AUTH_WINDOW_SECONDS * 2]
    for ip in stale:
        del _auth_attempts[ip]


def _rate_limit_auth(ip: str) -> None:
    _cleanup_rate_limiters()
    now = time.time()
    _auth_attempts[ip] = [t for t in _auth_attempts[ip] if now - t < AUTH_WINDOW_SECONDS]
    if len(_auth_attempts[ip]) >= AUTH_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts — try again later")
    _auth_attempts[ip].append(now)


def _sign_token(token_id: str, ts: int) -> str:
    payload = f"{token_id}:{ts}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_token(token: str) -> bool:
    try:
        token_id, ts_str, sig = token.split(":", 2)
        ts = int(ts_str)
        if time.time() - ts > TOKEN_TTL:
            return False
        expected_payload = f"{token_id}:{ts_str}"
        expected = hmac.new(SECRET_KEY.encode(), expected_payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except (ValueError, KeyError):
        return False


def _require_auth(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and _verify_token(auth[7:]):
        return None
    cookie = request.cookies.get("loglens_token")
    if cookie and _verify_token(cookie):
        return None
    return "unauthorized"


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class AuthBody(BaseModel):
    api_key: str


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/auth")
async def authenticate(request: Request, body: AuthBody):
    ip = _client_ip(request)
    _rate_limit_auth(ip)

    if not hmac.compare_digest(body.api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    ts = int(time.time())
    token_id = hashlib.sha256(f"{ts}:{body.api_key}".encode()).hexdigest()[:32]
    token = _sign_token(token_id, ts)
    response = JSONResponse({"token": token, "expires_in": TOKEN_TTL})
    secure = request.url.scheme == "https"
    response.set_cookie("loglens_token", token, httponly=True, samesite="strict", max_age=TOKEN_TTL, secure=secure)
    return response


@app.post("/api/logout")
async def logout(request: Request):
    response = JSONResponse({"ok": True})
    secure = request.url.scheme == "https"
    response.delete_cookie("loglens_token", secure=secure)
    return response


@app.get("/api/session")
async def check_session(request: Request):
    cookie = request.cookies.get("loglens_token")
    if cookie and _verify_token(cookie):
        try:
            _, ts_str, _ = cookie.split(":", 2)
            ts = int(ts_str)
            remaining = max(0, TOKEN_TTL - (int(time.time()) - ts))
        except Exception:
            remaining = 0
        return JSONResponse({"authenticated": True, "expires_in": remaining})
    return JSONResponse({"authenticated": False}, status_code=401)


@app.post("/api/analyze")
async def analyze(request: Request, file: UploadFile = File(None), log_type: str = Form("auto"), exclude_ips: str = Form(""), slow_threshold: str = Form(""), critical_threshold: str = Form("")):
    auth_err = _require_auth(request)
    if auth_err:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if file:
        raw_bytes = b""
        total_read = 0
        while True:
            chunk = await file.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="File too large (max 50MB)")
            raw_bytes += chunk
        raw = raw_bytes.decode("utf-8", errors="replace")
    else:
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        raw = body.get("content", "")
        log_type = body.get("log_type", "auto")
        exclude_ips = body.get("exclude_ips", "")
        slow_threshold = body.get("slow_threshold", "")
        critical_threshold = body.get("critical_threshold", "")

    if not raw.strip():
        raise HTTPException(status_code=400, detail="No log content provided")

    skip = [ip.strip() for ip in exclude_ips.split(",") if ip.strip()] if exclude_ips else []

    # Apply per-session thresholds if provided
    import app.config as _cfg
    _orig_slow = _cfg.SLOW_THRESHOLD
    _orig_critical = _cfg.CRITICAL_THRESHOLD
    if slow_threshold:
        try: _cfg.SLOW_THRESHOLD = float(slow_threshold)
        except ValueError: pass
    if critical_threshold:
        try: _cfg.CRITICAL_THRESHOLD = float(critical_threshold)
        except ValueError: pass

    try:
        report, parser = parse_and_analyze(raw, log_type, exclude_ips=skip or None, return_parser=True)
    finally:
        _cfg.SLOW_THRESHOLD = _orig_slow
        _cfg.CRITICAL_THRESHOLD = _orig_critical

    if report.get("error"):
        return JSONResponse(report)
    analysis_id = _cache_analysis(parser, report)
    report["analysis_id"] = analysis_id
    report["slow_threshold"] = _cfg.SLOW_THRESHOLD
    report["critical_threshold"] = _cfg.CRITICAL_THRESHOLD
    return JSONResponse(report)


@app.get("/api/context/{analysis_id}/{entry_idx}")
async def get_context(analysis_id: str, entry_idx: int, request: Request, before: int = 5, after: int = 5):
    auth_err = _require_auth(request)
    if auth_err:
        raise HTTPException(status_code=401, detail="Unauthorized")
    _cleanup_analysis_cache()
    cached = _analysis_cache.get(analysis_id)
    if not cached:
        raise HTTPException(status_code=404, detail="Analysis not found or expired (5 min TTL)")
    context = cached["parser"].get_context(entry_idx, before=before, after=after)
    if "error" in context:
        raise HTTPException(status_code=400, detail=context["error"])
    return JSONResponse(context)


@app.post("/api/analyze-batch")
async def analyze_batch(request: Request):
    auth_err = _require_auth(request)
    if auth_err:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    files = body.get("files", [])
    log_type = body.get("log_type", "auto")
    exclude_ips = body.get("exclude_ips", "")
    label = body.get("label", "")
    slow_threshold = body.get("slow_threshold", "")
    critical_threshold = body.get("critical_threshold", "")

    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    skip = [ip.strip() for ip in exclude_ips.split(",") if ip.strip()] if exclude_ips else []

    # Apply per-session thresholds if provided
    import app.config as _cfg
    _orig_slow = _cfg.SLOW_THRESHOLD
    _orig_critical = _cfg.CRITICAL_THRESHOLD
    if slow_threshold:
        try: _cfg.SLOW_THRESHOLD = float(slow_threshold)
        except ValueError: pass
    if critical_threshold:
        try: _cfg.CRITICAL_THRESHOLD = float(critical_threshold)
        except ValueError: pass

    try:
        reports = []
        for f in files:
            content = f.get("content", "")
            fname = f.get("name", "unknown")
            if not content.strip():
                reports.append({"error": f"No content in {fname}", "filename": fname})
                continue
            r, p = parse_and_analyze(content, log_type, exclude_ips=skip or None, return_parser=True)
            if not r.get("error"):
                aid = _cache_analysis(p, r)
                r["analysis_id"] = aid
                r["slow_threshold"] = _cfg.SLOW_THRESHOLD
                r["critical_threshold"] = _cfg.CRITICAL_THRESHOLD
            r["filename"] = fname
            reports.append(r)
    finally:
        _cfg.SLOW_THRESHOLD = _orig_slow
        _cfg.CRITICAL_THRESHOLD = _orig_critical

    return JSONResponse({"reports": reports, "count": len(reports), "label": label})


@app.post("/api/analyze-correlate")
async def analyze_correlate(request: Request):
    auth_err = _require_auth(request)
    if auth_err:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    files = body.get("files", [])
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    skip = []
    exclude_ips = body.get("exclude_ips", "")
    if exclude_ips:
        skip = [ip.strip() for ip in exclude_ips.split(",") if ip.strip()]

    parsed_files = []
    for f in files:
        content = f.get("content", "")
        fname = f.get("name", "unknown")
        log_type = f.get("log_type", "auto")
        if not content.strip():
            continue
        r, p = parse_and_analyze(content, log_type, exclude_ips=skip or None, return_parser=True)
        if r.get("error"):
            continue
        r["filename"] = fname
        parsed_files.append({"report": r, "parser": p, "filename": fname})

    if not parsed_files:
        raise HTTPException(status_code=400, detail="No valid logs to correlate")

    all_entries = []
    for pf in parsed_files:
        report = pf["report"]
        filename = pf["filename"]
        log_type = report.get("detected_type", "unknown")
        for i, entry in enumerate(report.get("_entries", [])):
            all_entries.append({
                "timestamp": entry.get("timestamp", ""),
                "type": log_type,
                "source": filename,
                "entry": entry,
                "line_num": report.get("_line_numbers", [])[i] if i < len(report.get("_line_numbers", [])) else 0,
            })

    for entry in all_entries:
        entry["_sort_key"] = entry["timestamp"]
    all_entries.sort(key=lambda x: x["_sort_key"])

    timeline = []
    for entry in all_entries:
        ts = entry["timestamp"]
        etype = entry["type"]
        source = entry["source"]
        e = entry["entry"]
        summary = _make_entry_summary(e, etype)
        timeline.append({
            "timestamp": ts,
            "type": etype,
            "source": source,
            "summary": summary,
            "entry": e,
        })

    type_counts = defaultdict(int)
    for entry in all_entries:
        type_counts[entry["type"]] += 1

    return JSONResponse({
        "correlation": {
            "timeline": timeline,
            "total_events": len(all_entries),
            "type_counts": dict(type_counts),
            "sources": [pf["filename"] for pf in parsed_files],
            "reports": [pf["report"] for pf in parsed_files],
        }
    })


def _make_entry_summary(entry: dict, log_type: str) -> str:
    if log_type == "nginx_access":
        return f"{entry.get('method', '?')} {entry.get('path', '?')} → {entry.get('status', '?')}"
    elif log_type == "nginx_error":
        return entry.get("message", str(entry)[:120])
    elif log_type == "syslog":
        return f"{entry.get('process', '?')}: {entry.get('message', str(entry)[:100])}"
    elif log_type == "container":
        return f"[{entry.get('stream', '?')}] {entry.get('message', entry.get('log', str(entry)[:100]))}"
    elif log_type == "api_backend":
        return f"{entry.get('level', '?')}: {entry.get('message', str(entry)[:100])}"
    elif log_type == "postgres":
        return f"{entry.get('level', '?')}: {entry.get('message', str(entry)[:100])}"
    return str(entry)[:120]
