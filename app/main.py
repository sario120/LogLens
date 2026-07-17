import hashlib
import hmac
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import (
    API_KEY, SECRET_KEY, TOKEN_TTL, MAX_UPLOAD_BYTES, UPLOAD_CHUNK_SIZE,
    AUTH_MAX_ATTEMPTS, AUTH_WINDOW_SECONDS,
)
from app.analyzers.report import parse_and_analyze

app = FastAPI(title="LogLens", version="1.0.0", docs_url=None, redoc_url=None)

BASE = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))

# --- rate limiter: per-IP, sliding window ---
_auth_attempts: dict[str, list[float]] = defaultdict(list)


def _rate_limit(ip: str) -> None:
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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/auth")
async def authenticate(request: Request, body: dict):
    ip = _client_ip(request)
    _rate_limit(ip)

    key = body.get("api_key", "")
    if not hmac.compare_digest(key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    ts = int(time.time())
    token_id = hashlib.sha256(f"{ts}:{key}".encode()).hexdigest()[:32]
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
async def analyze(request: Request, file: UploadFile = File(None), log_type: str = Form("auto"), exclude_ips: str = Form("")):
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
        body = await request.json()
        raw = body.get("content", "")
        log_type = body.get("log_type", "auto")
        exclude_ips = body.get("exclude_ips", "")

    if not raw.strip():
        raise HTTPException(status_code=400, detail="No log content provided")

    skip = [ip.strip() for ip in exclude_ips.split(",") if ip.strip()] if exclude_ips else []
    report = parse_and_analyze(raw, log_type, exclude_ips=skip or None)
    return JSONResponse(report)
