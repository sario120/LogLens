import hashlib
import hmac
import time
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import API_KEY, SECRET_KEY, DEBUG
from app.parsers import LOG_TYPES
from app.analyzers.report import parse_and_analyze

app = FastAPI(title="LogLens", version="1.0.0", docs_url=None, redoc_url=None)

BASE = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))

TOKEN_TTL = 3600


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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/auth")
async def authenticate(request: Request, body: dict):
    key = body.get("api_key", "")
    if not hmac.compare_digest(key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    ts = int(time.time())
    token_id = hashlib.sha256(f"{ts}:{key}".encode()).hexdigest()[:32]
    token = _sign_token(token_id, ts)
    response = JSONResponse({"token": token, "expires_in": TOKEN_TTL})
    response.set_cookie("loglens_token", token, httponly=True, samesite="strict", max_age=TOKEN_TTL)
    return response


@app.get("/api/log-types")
async def log_types(request: Request):
    auth_err = _require_auth(request)
    if auth_err:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"types": LOG_TYPES}


@app.post("/api/analyze")
async def analyze(request: Request, file: UploadFile = File(None), log_type: str = Form("auto"), exclude_ips: str = Form("")):
    auth_err = _require_auth(request)
    if auth_err:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if file:
        raw_bytes = await file.read()
        raw = raw_bytes.decode("utf-8", errors="replace")
    else:
        body = await request.json()
        raw = body.get("content", "")
        log_type = body.get("log_type", "auto")
        exclude_ips = body.get("exclude_ips", "")

    if not raw.strip():
        raise HTTPException(status_code=400, detail="No log content provided")

    max_size = 50 * 1024 * 1024
    if len(raw.encode("utf-8")) > max_size:
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")

    skip = [ip.strip() for ip in exclude_ips.split(",") if ip.strip()] if exclude_ips else []
    report = parse_and_analyze(raw, log_type, exclude_ips=skip or None)
    return JSONResponse(report)
