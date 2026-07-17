# Knight

A fast, **fail-open** Web Application Firewall / intrusion-detection guard.

Knight sits beside nginx on a bastion or edge host. nginx asks it to vet **every
request** before forwarding to the real service, and Knight also tails the nginx
access log out of band. Most of the time it just watches; when a request matches
its ruleset, Knight bans the source IP and the request is refused.

> **Fail-open by design:** nginx stays the real front door. If Knight crashes or
> is unreachable, nginx is configured to serve traffic anyway — a Knight outage
> never takes your site down.

---

## How it works

```
        ┌──────────────── every request ─────────────────┐
Client → nginx ── auth_request ─► Knight /inspect ──► 204 allow / 403 block
   │        │   (fails OPEN if Knight is down)            │
   │        └──► backend  (only when allowed)             │
   │                                                      │
   └── /var/log/nginx/access.log ── tail ─► Knight observer ┘
                                            (aggregate/slow attacks → ban IP)
```

Two paths share **one detection engine**:

- **Inline (real-time):** nginx `auth_request` calls `POST /inspect`. Knight
  answers `204` (allow) or `403` (block). This can stop the very first malicious
  request.
- **Out-of-band (observer):** Knight tails the access log and replays each line
  through the engine, catching abuse that's only visible in aggregate. Even in
  pure log mode it can ban offenders.

### The detection engine ("observe fast, strike only when needed")

Every request runs a two-stage pipeline:

1. **Aho-Corasick prefilter** — all rule *keywords* are compiled into one
   automaton. A single `O(n)` scan of the request finds which keywords are
   present. Rules whose keyword didn't appear are skipped entirely, so benign
   traffic is vetted for almost nothing.
2. **Regex confirm + anomaly scoring** — surviving candidate rules run their
   RE2 regex (linear time, no catastrophic backtracking) against their specific
   targets. Each firing rule adds its `severity` to an anomaly score
   (OWASP-CRS style). The request is blocked if any rule's `action` is `block`
   **or** the total score reaches `anomaly_threshold`.

Enforcement primitives:

- **IP blocklist** — TTL-based bans, checked on the fast path before the engine.
- **Per-IP token-bucket rate limiter** — catches volumetric abuse (scanners,
  brute force) that no single-request signature would.

---

## Project layout

```
cmd/knight/            entrypoint
internal/
  ahocorasick/         multi-pattern prefilter (zero-dependency)
  request/             request normalization (URL-decode, lower-case)
  engine/              rule model, loader, two-stage evaluation
  guard/               IP blocklist + rate limiter
  server/              /inspect, /healthz, /metrics, /blocklist
  observer/            nginx access-log tailer
config.json            runtime config
rules/signatures.json  the ruleset (edit this to add signatures)
deploy/nginx.conf.example
```

No third-party modules — Knight builds into a single static binary.

---

## Build & run

Knight needs the Go toolchain (not currently installed on this machine):

```bash
# install Go (Ubuntu)
sudo apt-get update && sudo apt-get install -y golang-go
# or grab the latest from https://go.dev/dl/

# from the project root:
go test ./...            # run the test suite
go build -o knight ./cmd/knight
./knight -config config.json
```

Then point nginx at it using `deploy/nginx.conf.example`.

### Try it without nginx

```bash
# allowed
curl -i localhost:8088/inspect \
  -H 'X-Real-IP: 9.9.9.9' -H 'X-Original-URI: /products?id=42'

# blocked (SQL injection) — note: only bans in enforce mode
curl -i localhost:8088/inspect \
  -H 'X-Real-IP: 9.9.9.9' \
  -H 'X-Original-URI: /item?id=1 union select pw from users'

curl -s localhost:8088/metrics
curl -s localhost:8088/blocklist
```

---

## Configuration (`config.json`)

| Field | Meaning |
|-------|---------|
| `listen` | Address the decision API binds to (keep it on localhost). |
| `mode` | `observe` = log what *would* be blocked but allow everything (safe rollout). `enforce` = actually block & ban. |
| `anomaly_threshold` | Total rule score at/above which a request is blocked. |
| `ban.duration` | How long an offending IP stays banned, e.g. `15m`, `1h`. |
| `rate_limit.requests_per_second` / `burst` | Per-IP token bucket (`0` disables). |
| `observer.enabled` / `access_log` / `block_threshold` | Out-of-band log tailer. |

**Roll out safely:** start in `observe`, watch `/metrics` and the `would block`
log lines, tune out false positives, then switch to `enforce`.

---

## Writing rules (`rules/signatures.json`)

```json
{
  "id": "SQLI-001",
  "name": "SQL injection: UNION SELECT",
  "severity": 10,
  "targets": ["query", "uri", "body"],
  "keywords": ["union", "select"],
  "regex": "union[\\s\\S]{0,40}select",
  "action": "",
  "tags": ["sqli"]
}
```

- `keywords` double as the prefilter. **Give every regex rule at least one cheap
  literal keyword that must be present for the regex to match** (e.g. `select`,
  `<script`, `../`) — otherwise the rule runs on every request.
- `targets`: `path`, `query`, `uri`, `user_agent`, `referer`, `cookie`, `body`,
  or `any`.
- `action: "block"` forces a block on a single high-confidence hit; otherwise
  severity accumulates toward `anomaly_threshold`.

Ships with starter signatures for SQLi, XSS, path traversal, sensitive-file
access, command injection, RFI/PHP wrappers, Log4Shell, and known scanner UAs.

---

## Roadmap / not yet built

- Request **body** inspection on the inline path (auth_request only sees
  headers; needs an OpenResty/Lua hook or a full reverse-proxy mode).
- Push bans to `nftables`/`fail2ban` for kernel-level dropping.
- Hot rule reload (SIGHUP) and a Prometheus metrics format.
- Per-rule false-positive counters and a small admin UI.

## Scope & ethics

Knight is a **defensive** tool for protecting services you operate. Only deploy
it in front of infrastructure you own or are authorized to protect.
