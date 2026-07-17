# Knight

A lightweight nginx traffic observability agent — think **Sentry for web
traffic, at the network layer**. Knight tails your nginx access logs, turns
every request into analytics (status-code breakdowns, per-IP behaviour,
per-endpoint health), lets you drill into *why* requests are failing, and can
notify you by webhook or email when something looks wrong.

It **observes only** — it never blocks, bans, or modifies traffic. Zero code
changes to the app it's watching.

> Looking for the WAF/intrusion-blocking design (inline `auth_request`,
> IP banning, SQLi/XSS signatures)? That code still lives in this repo
> (`internal/engine`, `internal/guard`, `internal/sentinel`, `internal/server`)
> but is **parked, unwired** — a later layer. Everything below describes what
> actually runs today.

---

## How it works

```
                    ┌── nginx access log(s) ──┐
                    │   (file / dir / glob,    │
                    │    plain or .gz)         │
                    └───────────┬──────────────┘
                                │ tail
                                ▼
                     ┌─────────────────────┐        webhook
                     │   Knight agent      │───┬──▶ email
                     │ (single Go binary)  │   │    (on threshold /
                     └──────────┬──────────┘   │     anomaly)
                                │ JSON API       │
                                │ (127.0.0.1:8090)
                                ▼
                     dashboard (FE-Knight, separate repo)
```

Every log line is parsed, its URL is normalized into an **endpoint template**
(`/api/users/12345` → `/api/users/{id}`, dynamic UUIDs/tokens collapsed the
same way), and folded into an in-memory store. Failing requests (`status >=
400`) are additionally retained individually so their query strings can be
broken into report columns later.

No database, no third-party modules — `go build` produces a single static
binary.

---

## Quick install (Ubuntu / Debian)

```bash
curl -fsSL <your-apt-repo-url>/install.sh | sh
```

This adds a signed APT repository and installs `knight` as a systemd service
running under a dedicated, unprivileged `knight` user (in the `adm` group so
it can read `/var/log/nginx`). See [`packaging/`](packaging/) for how the
repo and `.deb` are built, and [`packaging/README.md`](packaging/README.md)
for operating the installed service.

## Build from source

```bash
go test ./...
go build -o knight ./cmd/knight
./knight -config config.json
```

Flags:

| Flag | Meaning |
|---|---|
| `-config <path>` | config file (default `config.json`) |
| `-from-start` | read existing log files from the beginning, not just new lines — for analyzing logs you already have |
| `-since "<dd/mm/yyyy:hh:mm:ss>"` | only ingest requests at/after this time; implies `-from-start` |

Without either flag, Knight tails **only new** lines (normal live-monitoring
mode) so a restart never re-ingests gigabytes of history.

---

## Configuration (`config.json`)

```json
{
  "sites": [
    { "name": "myapp", "access_log": "/var/log/nginx/access.log" }
  ],
  "analytics": {
    "api_listen": "127.0.0.1:8090",
    "retention": "24h",
    "route_patterns": ["/api/users/:id/orders/:orderId"]
  },
  "alerts": {
    "enabled": true,
    "rules": [
      { "id": "high-5xx", "metric": "status_count", "status_classes": [5],
        "window": "2m", "threshold": 5, "channels": ["webhook"] },
      { "id": "ip-flood", "metric": "ip_request_count",
        "window": "1m", "threshold": 100 }
    ],
    "anomaly": { "enabled": true },
    "webhook": { "enabled": true, "url": "https://your-endpoint", "secret": "..." },
    "email":   { "enabled": true, "smtp_host": "smtp.example.com", "smtp_port": 587,
                 "from": "knight@example.com", "to": ["ops@example.com"] }
  }
}
```

- **`sites[].access_log`** accepts a single file, a directory, or a glob
  (`/var/log/nginx/access.log*`) — one entry can cover a whole logrotate set,
  including `.gz` archives, when read historically.
- **`analytics.route_patterns`** override the automatic URL grouping. Syntax:
  `:name` for a dynamic segment, e.g. `/api/users/:id`. First match wins; paths
  matching nothing are auto-templated heuristically (digits→`{id}`,
  UUID→`{uuid}`, long tokens→`{token}`).
- **`alerts.rules`** are user-defined thresholds: *"N matching requests in a
  window"* (`status_count`, scoped to a status class and optionally one site)
  or *"one IP makes N requests in a window"* (`ip_request_count`, flood/scanner
  detection).
- **`alerts.anomaly`** is a threshold-free spike detector: it compares a recent
  4xx/5xx rate against that **site's own** rolling baseline (mean +
  `sensitivity`×stddev — an adaptive control-chart/Z-score test), so it adapts
  per site instead of using one fixed percentage. Tuned by default to avoid
  false alarms on low-traffic blips (minimum sample size + absolute rate
  floor + cooldown).
- **Alerts are LIVE-only** — the rule evaluator never runs during
  `-from-start`/`-since` historical replay, so re-analyzing old logs never
  fires stale notifications.

The config can also be read/edited at runtime — see the API below — and the
dashboard's Configuration page is the primary way most users will manage it.

---

## API (`127.0.0.1:8090` by default)

All routes are read-only `GET` except the config-write endpoints, which only
mount if the agent was started with config-write support wired up (always,
via `cmd/knight`).

| Route | Purpose |
|---|---|
| `GET /v1/overview` | totals + success/redirect/failure/error rates |
| `GET /v1/series?bucket=&count=` | fixed-shape time series (e.g. `bucket=1h&count=24`), anchored to the latest ingested data so historical logs render correct dates |
| `GET /v1/endpoints` | busiest endpoints (grouped), with health per endpoint |
| `GET /v1/ips` / `GET /v1/ips/{ip}` | busiest source IPs / one IP's full breakdown |
| `GET /v1/report/endpoints` | distinct **failing** endpoints (4xx/5xx), for drill-down |
| `GET /v1/report/keys?endpoint=` | query-param keys discovered on that endpoint's failures, with coverage % |
| `GET /v1/report/rows?endpoint=&keys=` | the report table (add `&format=csv` to download) |
| `GET /v1/config` / `PUT /v1/config` | read / hot-reload the runtime config |
| `POST /v1/config/validate` | validate an edit without saving |
| `POST /v1/config/test-log` | check whether a candidate log path is readable |
| `POST /v1/config/preview-route` | preview how a URL groups under draft patterns |
| `POST /v1/alerts/test` | send a synthetic alert to verify webhook/email credentials |
| `GET /healthz` | plain `200 ok` liveness check |

## Failure drill-down reports

Point Knight at a failing endpoint and it will:

1. list distinct failing endpoints (4xx/5xx), busiest first,
2. discover every query-string key present on that endpoint's failures
   (with coverage %), and
3. produce a table — `date · ip · status · method · endpoint` plus one column
   per key you select — exportable as CSV.

This turns a URL like
`GET /api/lumpsum/get-redirection-url?ihNo=...&apiKey=...&fundCode=...` into a
readable table for spotting patterns (a bad `apiKey`, a specific `fundCode`
that always fails, etc.) without writing a single grep.

---

## Dashboard

The web dashboard (Overview, Endpoints, IPs, Reports, Configuration) is a
separate project — a Vite + React + TypeScript SPA that talks to this agent's
JSON API. Apple-style monochrome design; semantic color reserved for
success/redirect/failure/error states.

---

## Packaging

See [`packaging/`](packaging/):

- `build-deb.sh` — builds a static, stripped binary and packages it as a
  `.deb` with a hardened systemd unit and a dedicated unprivileged user.
- `build-repo.sh <url>` — builds a signed APT repository (GPG-signed
  `Release`/`InRelease`, `Packages` index) from the `.deb`, plus a one-line
  `install.sh` for end users. GitHub Pages-ready (`.nojekyll` included) — a
  public repo with Pages enabled needs no separate domain.

---

## Roadmap / not yet built

- **X-Forwarded-For parsing** — nginx currently logs the proxy/load-balancer
  IP for every request, so per-IP analytics show one IP until this lands.
- **arm64 package** — the `.deb`/apt repo currently ship amd64 only.
- Cloud control-plane + hosted dashboard, CLI subcommands.
- The parked WAF/intrusion-blocking layer (inline `auth_request` blocking,
  Aho-Corasick + RE2 signature engine, TTL IP blocklist, nftables kernel bans,
  port-scan sentinel) — a later layer, not removed.

## Scope & ethics

Knight is a tool for observing traffic on infrastructure you own or are
authorized to operate. Only point it at logs you have permission to analyze.
