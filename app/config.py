import os

API_KEY = os.getenv("LOGS_PORTAL_API_KEY", "changeme")
SECRET_KEY = os.getenv("LOGS_PORTAL_SECRET", "internal-portal-secret-change-in-prod")
HOST = os.getenv("LOGS_PORTAL_HOST", "0.0.0.0")
PORT = int(os.getenv("LOGS_PORTAL_PORT", "8600"))
DEBUG = os.getenv("LOGS_PORTAL_DEBUG", "false").lower() == "true"
