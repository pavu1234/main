# WebGuard Pro

WebGuard Pro is an authorized website vulnerability scanner and security-analysis dashboard. It performs low-impact, non-destructive checks against a website you own or are explicitly permitted to test. Results come from live backend requests; the product does not populate a fake finding list.

## What it checks

- Same-host asynchronous crawling with page/depth/request caps
- SSRF protections for localhost, private, link-local, reserved, metadata and unsupported schemes
- Redirect re-validation and same-host scope enforcement
- HTTP security headers and clickjacking protections
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- HTTPS/TLS certificate and protocol observations
- CORS policy observations
- Mixed content, forms, verbose errors and version disclosure
- Small controlled checks for `robots.txt`, `sitemap.xml`, `security.txt`, `.git/HEAD` and `.env`
- Static JavaScript checks, dangerous DOM-sink indicators, development URLs, probable secrets and source maps
- Safe reflection tests and non-destructive SQL-error heuristics for existing query parameters
- Finding severity, confidence, OWASP/CWE mapping when appropriate, reviewer status and notes
- Scan history, comparison, page inventory, SSE progress and PDF/JSON/CSV reports

## Safety model

WebGuard intentionally does **not** include brute force, credential stuffing, account takeover, destructive injection, data extraction, command execution, reverse shells, persistence, authentication bypass exploitation, WAF evasion, DoS/stress testing or Internet-wide scanning.

Normal scans reject private/internal IP space. The bundled vulnerable lab is accessible only through the dedicated Demo Scan endpoint, which marks the scan as an internal demo. Keep the lab local; the Compose file exposes it only to the internal Docker network.

DNS is validated before each request and again when following redirects. This substantially reduces SSRF exposure, but production deployments should also enforce egress firewall rules because application-layer DNS checks alone cannot eliminate every DNS-rebinding race.

## Architecture

```text
frontend/        React + TypeScript + Vite + Recharts
backend/         FastAPI + HTTPX + BeautifulSoup + SQLAlchemy
security-lab/    local-only intentionally weak FastAPI app
docker-compose.yml
```

The backend separates scope validation, HTTP transport, crawling, checks, persistence, scoring, sanitization and reporting. SQLite is the default database and SQLAlchemy makes migration to PostgreSQL straightforward.

## Quick start with Docker

```bash
docker compose up --build
```

Open `http://localhost:5173`.

Use **Demo Scan** to test against the bundled local lab. For an external target, enter an `http://` or `https://` URL and confirm that you own the site or have explicit authorization.

## Backend setup

```bash
cd backend
python -m venv venv
```

Windows:

```powershell
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Then:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Vite proxies `/api` to `http://localhost:8000` in local development.

## Running tests

```bash
cd backend
pytest -q
```

```bash
cd frontend
npm test
```

## API

- `POST /api/scans`
- `POST /api/scans/demo`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans/{scan_id}/pages`
- `GET /api/scans/{scan_id}/requests`
- `GET /api/scans/{scan_id}/events`
- `PATCH /api/findings/{finding_id}`
- `DELETE /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/report/pdf`
- `GET /api/scans/{scan_id}/report/json`
- `GET /api/scans/{scan_id}/report/csv`

Example request:

```json
{
  "target": "https://example.com",
  "authorized": true,
  "max_pages": 25,
  "max_depth": 2,
  "concurrency": 5,
  "follow_redirects": true,
  "scan_javascript": true,
  "analyze_forms": true,
  "passive_only": false
}
```

## Methodology and interpretation

A missing header is reported as a configuration weakness, not proof of exploitability. A reflected marker is reported as a reflected-input concern, not automatically as XSS. A database error signature is reported as a potential SQL-related error-handling issue, not automatically as SQL injection. Static JavaScript sinks are cues for manual review rather than vulnerability confirmation.

Every exported report includes this limitation:

> Automated security scanning cannot identify every security vulnerability. Results may contain false positives or false negatives. Findings requiring exploitation, authenticated business-logic analysis or manual testing should be reviewed by an authorized security professional.

## Production hardening recommendations

For real multi-user deployment, add authentication and per-user scan ownership, PostgreSQL, a durable task queue, egress network policies, TLS termination, rate limits at the API gateway, audit logging, encrypted storage, retention rules and explicit allowlists for high-trust environments.
