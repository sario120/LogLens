# LogLens

Lightweight, self-hosted log analysis portal. Paste or upload log files and get instant interactive reports with charts, metrics, incident detection, and cross-references — nothing stored on disk.

## Features

- **Interactive Reports** — timeline charts, status distribution, endpoint performance, IP analysis, hourly aggregation
- **6 Log Parsers** — nginx access/error, container (Docker/K8s), syslog/auth.log, API backend (JSON/structured), PostgreSQL
- **Auto-Detection** — identifies log type automatically with confidence scoring
- **Batch Comparison** — upload multiple files side-by-side with per-file and cross-reference views
- **Raw Log Browser** — click any error or incident to jump to the exact source line
- **Session Labels** — name your analysis runs for easy retrieval
- **Report History** — all past analyses saved locally in your browser (IndexedDB)
- **PDF Export** — landscape A3 reports with full charts and tables
- **Text Summary** — plain-text export for team chat and incident reports
- **Dark / Light Theme** — automatic system preference detection with manual toggle
- **IP Exclusion** — filter out known IPs before analysis
- **Performance Thresholds** — configurable slow/critical thresholds per analysis
- **Browser Notifications** — get notified when analysis completes
- **Collapsible Sections** — expand/collapse report sections for faster navigation
- **Search & Filter** — full-text search across all tables, click-to-filter, column sorting

## Supported Log Types

| Parser | Format |
|--------|--------|
| **Nginx Access** | Combined, combined+json, with optional upstream timing fields |
| **Nginx Error** | Standard nginx error log |
| **Container** | Docker, Kubernetes, systemd-journald, generic `timestamp level message` |
| **Syslog / Auth** | BSD syslog, rsyslog, `/var/log/auth.log` — including SSH bruteforce and failed login detection |
| **API Backend** | JSON-lines, `timestamp level [component] message`, and structured formats |
| **PostgreSQL** | Standard CSV and stderr log format with query normalization, lock detection, autovacuum analysis, and replication lag monitoring |

## Quick Start

### Docker (recommended)

```bash
# Clone and configure
git clone https://github.com/sario120/LogLens.git
cd LogLens
cp .env.example .env

# Generate a secure secret
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# Paste the output as both LOGS_PORTAL_API_KEY and LOGS_PORTAL_SECRET in .env

# Start
docker compose up -d --build
```

Open **http://localhost:8600** — enter the API key from your `.env` to log in.

### Local (venv)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your values

python run.py
```

## Configuration

All settings are controlled via environment variables. See [`.env.example`](.env.example) for the full list with descriptions.

| Variable | Default | Description |
|----------|---------|-------------|
| `LOGS_PORTAL_API_KEY` | *(required)* | API key for browser login |
| `LOGS_PORTAL_SECRET` | *(required)* | HMAC signing secret for session tokens |
| `LOGS_PORTAL_HOST` | `0.0.0.0` | Bind address |
| `LOGS_PORTAL_PORT` | `8600` | Listen port |
| `LOGS_PORTAL_WORKERS` | `2` | Uvicorn worker count |
| `LOGS_PORTAL_AUTH_MAX_ATTEMPTS` | `3` | Failed login attempts before lockout |
| `LOGS_PORTAL_AUTH_WINDOW_SECONDS` | `300` | Lockout duration (seconds) |
| `LOGS_PORTAL_MAX_UPLOAD_MB` | `50` | Max upload size (MB) |
| `LOGS_PORTAL_UPLOAD_CHUNK_KB` | `1024` | Upload chunk size (KB) |
| `LOGS_PORTAL_TOKEN_TTL` | `3600` | Session token lifetime (seconds) |
| `LOGS_PORTAL_SLOW_THRESHOLD` | `10.0` | Slow request threshold (seconds) |
| `LOGS_PORTAL_CRITICAL_THRESHOLD` | `30.0` | Critical request threshold (seconds) |
| `LOGS_PORTAL_DETECT_SAMPLE_SIZE` | `50` | Lines sampled for auto-detection |

The server **will not start** if `LOGS_PORTAL_API_KEY` or `LOGS_PORTAL_SECRET` are missing or left at their default values.

## Security

- **Stateless** — log content is processed in-memory and never written to disk
- **HMAC session tokens** — signed server-side, httponly cookies, no JWT library needed
- **Rate limiting** — per-IP lockout after failed auth attempts
- **No external dependencies at runtime** — all JS/CSS/fonts are self-hosted, zero CDN calls
- **Configurable resource limits** — Docker deployment capped at 256 MB / 0.5 CPU by default

## Architecture

```
logs_portal/
├── app/
│   ├── main.py              # FastAPI app — auth, rate limiting, upload, analysis endpoints
│   ├── config.py             # Environment variable loading and startup validation
│   ├── parsers/              # Log format parsers
│   │   ├── nginx_access.py
│   │   ├── nginx_error.py
│   │   ├── container.py
│   │   ├── syslog.py
│   │   ├── api_backend.py
│   │   └── postgres.py
│   └── analyzers/
│       └── report.py         # Report generation, log type detection, chart data
├── templates/
│   └── index.html            # Single-page Alpine.js frontend
├── static/                   # CSS, JS, favicon
├── Dockerfile                # Python 3.12-slim, ~240 MB image
├── docker-compose.yml        # Production-ready service definition
├── requirements.txt          # Python dependencies
├── run.py                    # Local development server
└── .env.example              # Configuration template
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth` | Authenticate with API key, receive session cookie |
| `POST` | `/api/logout` | Invalidate session |
| `GET` | `/api/session` | Check if current session is valid |
| `POST` | `/api/analyze` | Paste-based log analysis |
| `POST` | `/api/upload` | File upload and analysis |
| `POST` | `/api/batch` | Multi-file analysis |
| `POST` | `/api/correlate` | Cross-reference multiple log sources |
| `POST` | `/api/context` | Retrieve raw log context for a specific line |
| `GET` | `/` | Web interface |

## License

MIT
