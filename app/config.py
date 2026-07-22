import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# --- Auth ---
API_KEY = os.getenv("LOGS_PORTAL_API_KEY", "changeme")
SECRET_KEY = os.getenv("LOGS_PORTAL_SECRET", "internal-portal-secret-change-in-prod")

# --- Server ---
HOST = os.getenv("LOGS_PORTAL_HOST", "0.0.0.0")
PORT = int(os.getenv("LOGS_PORTAL_PORT", "8600"))
WORKERS = int(os.getenv("LOGS_PORTAL_WORKERS", "2"))

# --- Rate limiting ---
AUTH_MAX_ATTEMPTS = int(os.getenv("LOGS_PORTAL_AUTH_MAX_ATTEMPTS", "3"))
AUTH_WINDOW_SECONDS = int(os.getenv("LOGS_PORTAL_AUTH_WINDOW_SECONDS", "300"))

# --- Upload ---
UPLOAD_CHUNK_SIZE = int(os.getenv("LOGS_PORTAL_UPLOAD_CHUNK_KB", "1024")) * 1024

# --- Token ---
TOKEN_TTL = int(os.getenv("LOGS_PORTAL_TOKEN_TTL", "3600"))

# --- Performance thresholds (seconds) ---
SLOW_THRESHOLD = float(os.getenv("LOGS_PORTAL_SLOW_THRESHOLD", "10.0"))
CRITICAL_THRESHOLD = float(os.getenv("LOGS_PORTAL_CRITICAL_THRESHOLD", "30.0"))

# --- Auto-detection ---
DETECT_SAMPLE_SIZE = int(os.getenv("LOGS_PORTAL_DETECT_SAMPLE_SIZE", "50"))

_INSECURE_DEFAULTS = {
    "LOGS_PORTAL_API_KEY": "changeme",
    "LOGS_PORTAL_SECRET": "internal-portal-secret-change-in-prod",
}
_insecure = []
for env_var, default in _INSECURE_DEFAULTS.items():
    if os.getenv(env_var) is None or os.getenv(env_var) == default:
        _insecure.append(env_var)
if _insecure:
    print(f"[FATAL] Refusing to start — set these env vars to non-default values: {', '.join(_insecure)}", file=sys.stderr)
    sys.exit(1)
