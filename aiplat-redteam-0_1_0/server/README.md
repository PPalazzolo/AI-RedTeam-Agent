# aiplat-redteam — hosted MCP server

The cloud side of the `aiplat-redteam` plugin. It wraps the OWASP Agentic AI red team engine
(`agentic_redteam` + the garak suite) and exposes it over MCP (streamable HTTP) so Claude can
run a user's HTTP-reachable agent against the suite.

## Tools

| Tool | Purpose |
|---|---|
| `health()` | Liveness/readiness; reports whether garak is installed |
| `list_suites()` | ASI categories and garak probe sets available to run |
| `run_redteam(...)` | Run the suite against a target HTTP agent; returns a report dict |

`run_redteam` parameters: `target_url`, `prompt_field`, `response_field` (dotted path, `''` =
raw body), `method`, `auth_header`, `categories` (subset of ASI ids), `garak_set` (`''` to skip),
`garak_probes` (override), `generations` (≤3), `delay`. It returns
`{target, timestamp, summary, results[...], meta}` — `meta.connectivity_ok` flags a run where
most calls returned `[AGENT_ERROR]` (usually a wrong endpoint/auth/field mapping).

## Run locally

```bash
pip install -r requirements.txt          # add: pip install "garak>=0.17" to enable garak
export REDTEAM_PKG_DIR=/path/to/redteam   # dir containing agentic_redteam.py
python redteam_mcp_server.py              # serves MCP at http://0.0.0.0:8000/mcp
```

## Run with Docker

```bash
# from the repo root (contains redteam/ and aiplat-redteam-0_1_0/)
docker build -f aiplat-redteam-0_1_0/server/Dockerfile -t aiplat-redteam .
docker run -p 8000:8000 aiplat-redteam
```

Deploy the container to any host (Cloud Run, ECS, Fly, a VM, etc.) and expose it over HTTPS.
Point the plugin at it with `AIPLAT_REDTEAM_URL=https://your-host/mcp`.

## Security (operator responsibilities)

- **Authentication.** The plugin sends `Authorization: Bearer ${AIPLAT_REDTEAM_API_KEY}`. This
  server does not validate it on its own — put it behind an API gateway / reverse proxy (or your
  platform's auth) that verifies the bearer token before forwarding to `/mcp`. Do not expose the
  raw container publicly without that.
- **SSRF / egress.** `run_redteam` fetches a caller-supplied `target_url`. Run the server with a
  restricted egress policy (allowlist, no access to internal metadata endpoints or RFC1918 unless
  intended) so it can't be used to reach internal services.
- **Authorized testing only.** Ensure, via terms of use and/or gateway controls, that callers
  only target agents they own or are permitted to test.
- **Rate / size limits.** `generations` is capped at 3 and `delay` throttles target calls; add
  gateway-level rate limiting for multi-tenant use. `garak_set='full'` is slow — gate it.

## Notes

- garak is optional; without it the garak suite returns a single `INFO` row and ASI01–ASI10 still
  run. `health()` / `list_suites()` report `garak_available`.
- This is a stateless, synchronous v0.1.0: `run_redteam` blocks until the run completes (can take
  a few minutes). For long garak runs, consider fronting it with an async job layer.
