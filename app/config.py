import os
import sys

API_KEY = os.getenv("LOGS_PORTAL_API_KEY", "changeme")
SECRET_KEY = os.getenv("LOGS_PORTAL_SECRET", "internal-portal-secret-change-in-prod")
HOST = os.getenv("LOGS_PORTAL_HOST", "0.0.0.0")
PORT = int(os.getenv("LOGS_PORTAL_PORT", "8600"))

_INSECURE_DEFAULTS = {
    "LOGS_PORTAL_API_KEY": "changeme",
    "LOGS_PORTAL_SECRET": "internal-portal-secret-change-in-prod",
}
_insecure = []
for env_var, default in _INSECURE_DEFAULTS.items():
    if os.getenv(env_var) is None:
        _insecure.append(env_var)
if _insecure:
    print(f"[FATAL] Refusing to start — set these env vars: {', '.join(_insecure)}", file=sys.stderr)
    sys.exit(1)
