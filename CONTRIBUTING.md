# Contributing to LogLens

Thanks for your interest in contributing. LogLens is an internal log analysis tool — contributions are welcome for bug fixes, parser improvements, and test coverage.

## Getting Started

1. Clone the repo and create a virtual environment:
   ```bash
   git clone <repo-url> && cd LogLens
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Copy the environment file and set a dev API key:
   ```bash
   cp .env.example .env
   # Edit .env and set LOGS_PORTAL_API_KEY to any value for local dev
   ```

3. Run the server:
   ```bash
   python run.py
   ```

## Development

### Project structure

```
app/
  main.py            # FastAPI routes and middleware
  config.py          # Environment variable loading
  parsers/           # Log format parsers (nginx, syslog, container, etc.)
  analyzers/         # Report generation and log type detection
static/              # CSS, JS, theme
templates/           # Jinja2 HTML
tests/               # pytest test suite
```

### Code style

- Python: follow existing patterns, no new dependencies unless necessary
- Frontend: vanilla JS with Tailwind CSS, no build step
- Keep the app stateless — no log storage, process on-the-fly

### Running tests

```bash
source venv/bin/activate
pytest tests/ -v
coverage run -m pytest tests/
coverage report --fail-under=80
```

All tests must pass and coverage must stay above 80% before submitting.

### Adding a new parser

1. Create `app/parsers/your_format.py` extending `BaseParser`
2. Implement `_parse_line()` and `_build_report()`
3. Add auto-detection markers in `app/analyzers/report.py`
4. Add tests in `tests/test_your_format.py`
5. Update the README's supported formats table

### Commit messages

Use imperative mood, keep under 72 characters. Prefix with category when useful:

- `fix:` — bug fixes
- `feat:` — new features
- `test:` — test additions/fixes
- `docs:` — documentation changes
- `refactor:` — code restructuring without behavior change

## Submitting changes

1. Ensure all tests pass: `pytest tests/ -v`
2. Ensure coverage threshold met: `coverage report --fail-under=80`
3. Push your branch and open a pull request against `main`
4. Describe what changed and why in the PR description

## Reporting issues

Open an issue with:
- What you expected to happen
- What actually happened
- Sample log input (redact sensitive data) if reporting a parser bug
- Your environment (OS, Python version, Docker or bare metal)
