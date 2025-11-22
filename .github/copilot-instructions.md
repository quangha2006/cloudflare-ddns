# Copilot / AI assistant instructions for cloudflare-ddns

This repository is a small, single-process Python DDNS updater for Cloudflare, packaged for Linux and Docker. Use the notes below to make code changes, run locally, and produce safe, useful PRs.

**Big Picture:**
- **Single entrypoint:** `cloudflare-ddns.py` — contains all runtime logic (IP detection, Cloudflare API calls, record add/update/delete).
- **Config-driven:** runtime input is `config.json` loaded from `/data/config.json` (container) or `./config.json` (local). See `config-example.json` for exact schema.
- **Docker-first workflow:** `Dockerfile`, `docker-compose.yml`, and `scripts/` provide build/run flows. The container expects the repository root mounted at `/data` (or the config mapped to `/data/config.json`).

**Key files to inspect / change:**
- `cloudflare-ddns.py` — core logic. Look here for API usage patterns (`cf_api`), DNS housekeeping (`deleteEntries`, `commitRecord`), and the `--repeat` loop.
- `config-example.json` — canonical config schema: `cloudflare` array, `authentication` (either `api_token` OR `api_key` with `api_key`+`account_email`), `zone_id`, `subdomains`, `proxied` (object with `default` and per-subdomain boolean), and top-level `a`, `aaaa`, `repeattime`.
- `Dockerfile` / `docker-compose.yml` — how the image is built and how volumes/network are expected (`network_mode: host` is required for IPv6 access).
- `requirements.txt` — minimal deps: `requests`, `pytz`.
- `scripts/start-sync.sh` — how local venv runs the script (useful for manual debugging).

**Runtime behaviors & important patterns**
- The script polls Cloudflare and external IP providers (`https://1.1.1.1/cdn-cgi/trace`) for IPv4 and IPv6 and creates/updates DNS records.
- De-duplication: `commitRecord` searches existing records and will update the first match and delete duplicates — take care when changing record-matching logic.
- `proxied` can be a global default (`proxied.default`) and per-subdomain override (boolean). When changing proxied behavior, update the merge logic in `commitRecord`.
- The script uses a timezone hard-coded to `asia/ho_chi_minh` in `getDateTime()` for logs — change intentionally if adjusting log format.
- Graceful shutdown: `GracefulExit` uses `signal` + a threading Event; preserve this pattern when adding long-running behavior.

**Developer workflows / commands**
- Run once locally (reads `./config.json`):
  - `python3 -u cloudflare-ddns.py` (one-shot run)
- Run repeatedly (dev/test):
  - `python3 cloudflare-ddns.py --repeat` (uses `repeattime` from config, minutes)
- Quick local dev using venv: `./start-sync.sh` (sets up venv, installs `requests`, runs the script)
- Docker build (local / single-arch): `./scripts/docker-build.sh`
- Docker multi-arch: `./scripts/docker-build-all.sh` (Docker Buildx / experimental)
- Docker compose: `docker-compose up -d` — ensure `config.json` is available at `/data/config.json` inside the container (the provided compose mounts project root to `/data`).

**Testing & safety notes**
- There are no unit tests or CI in-tree — keep changes small and test locally with a disposable Cloudflare zone or a test API token.
- The script will delete DNS records it considers stale; be conservative when changing deletion logic. Prefer adding a dry-run flag if you need to validate behavior.

**Conventions to follow in PRs**
- Keep changes minimal and focused; this project prefers small, readable patches rather than large refactors.
- When editing `cloudflare-ddns.py`:
  - Maintain the single-file runtime model unless you extract files and update Dockerfile accordingly.
  - Preserve logging style and the timezone choice unless documentably required.
- When changing config schema, update `config-example.json` and README examples together.

**Integrations / externals**
- Cloudflare REST API v4 is used via `cf_api()`.
- External IP detection uses Cloudflare's trace endpoints (`1.1.1.1` for IPv4 and the IPv6 literal for IPv6).

**Useful code pointers (examples)**
- Where `config.json` is read: `readConfigFile()` and `config = readConfigFile(PATH + "/config.json")` in `__main__`.
- Where API auth is chosen: `cf_api()` checks `api_token` first, otherwise falls back to `X-Auth-Key` + `X-Auth-Email` headers.
- Where repeat behavior is triggered: check `if len(sys.argv) > 1 and sys.argv[1] == "--repeat"`.

License: this project is GPLv3 — be careful when proposing license-incompatible changes.

If anything here is unclear or you'd like conventions added (tests, CI, linting, or refactor guidance), tell me which area to expand and I will update this file.
