# Hotpot

Hotpot is a transparent HTTP/WebSocket reverse proxy, deception layer, bounded tarpit, and attack-intelligence service designed to sit in front of an existing Dockerized web application. Normal requests are forwarded unchanged. High-confidence probes are intercepted, classified, recorded, and answered by Hotpot instead of ever reaching the protected application.

```text
Internet -> host port -> Hotpot -> normal request -> existing app
                           |
                           +-> suspicious request
                                 |-> classify/fingerprint
                                 |-> update persistent offender history
                                 |-> deception or bounded tarpit
                                 `-> JSONL + SQLite intelligence
```

The protected application does not need code changes. Docker requires one networking change: its host-facing `ports:` mapping moves to Hotpot, while the application remains reachable on the Compose network.


## Repository layout

```text
hotpot/
├── .github/
│   ├── workflows/ci.yml
│   ├── workflows/docker-publish.yml
│   └── dependabot.yml
├── hotpot/                 # application code
├── profiles/               # deception/probe rules
├── tests/                  # unit + integration tests
├── .env.example
├── compose.example.yml
├── Dockerfile
├── Makefile
├── requirements.txt
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

## Repository and Docker image

The repository is structured to build and test on every push/pull request and publish a multi-platform Docker image to Docker Hub when you push a semantic Git tag. GitHub Actions never creates Git tags for you.

Configure these GitHub Actions repository secrets:

- `DOCKERHUB_USERNAME` — Docker Hub username or organization name
- `DOCKERHUB_TOKEN` — Docker Hub access token with permission to push the `hotpot` repository

Then publish a release image with:

```bash
git tag v0.1.0
git push origin v0.1.0
```

That tag publishes Docker aliases `0.1.0`, `0.1`, `0`, and `latest`. The workflow builds both `linux/amd64` and `linux/arm64`.

## Quick start

If an application currently publishes `3000:3000`:

```yaml
services:
  myapp:
    image: your/existing-image:latest
    expose:
      - "3000"
    networks: [hotpot_backend]

  hotpot:
    build: ./hotpot
    ports:
      - "3000:8080"
    environment:
      HOTPOT_UPSTREAM: http://myapp:3000
      HOTPOT_ADMIN_TOKEN: ${HOTPOT_ADMIN_TOKEN:-}
    volumes:
      - ./hotpot-data:/data
    networks: [hotpot_backend]
```

Set a long random token in your shell or `.env` if you want to use the dashboard:

```bash
HOTPOT_ADMIN_TOKEN='replace-with-a-long-random-value'
docker compose up -d --build
```

## Attack intelligence

Every matched probe is enriched with:

- source IP
- method and path
- attack profile/rule/category
- scanner/tool classification when recognizable
- scanner family
- stable 16-character behavioral fingerprint
- severity score
- repeat-offender score
- escalation level
- effective action (`deceive` or `tarpit`)

Persistent state is stored in `/data/hotpot.sqlite3`. Human-readable append-only events remain available in `/data/events.jsonl`.

### Scanner classification

Hotpot recognizes common HTTP-facing scanner User-Agents including WPScan, Nikto, sqlmap, Nuclei, Acunetix, Nessus, OpenVAS/Greenbone, Gobuster, DirBuster, dirsearch, ffuf, zgrab, Censys, and Shodan. Unknown scripted clients are labeled conservatively rather than assumed to be a specific scanner.

Fingerprints combine method, matched attack category/path, scanner family, and a normalized User-Agent. Tool version numbers are normalized so a routine scanner upgrade does not create a completely different fingerprint.

## Repeat-offender escalation

Hotpot maintains a durable score and hit count for each source IP. The default policy has four levels:

| Level | Typical threshold | Behavior |
|---|---|---|
| 1 | first/low-score probes | use the rule's configured action |
| 2 | 3+ probes or score 10+ | force tarpit, up to 1.5× base lifetime |
| 3 | 10+ probes or score 30+ | force tarpit, up to 2.25× base lifetime |
| 4 | 20+ probes or score 60+ | force tarpit, up to 3× base lifetime |

Escalated lifetimes are capped by `HOTPOT_TARPIT_ESCALATED_MAX_SECONDS` (default `60`). Crucially, escalation **never bypasses the global tarpit semaphore**. If the tarpit pool is full, Hotpot immediately serves the deception response instead of queueing another attacker.

## Tarpit behavior

Defaults:

- maximum concurrent tarpits: 10
- initial delay: 1 second
- delay between 32-byte chunks: 2 seconds
- base maximum lifetime: 20 seconds
- maximum escalated lifetime: 60 seconds
- full tarpit pool: immediate fake response, no wait queue

This wastes scanner time while keeping Hotpot's own resource consumption bounded.

## Dashboard

With `HOTPOT_ADMIN_TOKEN` configured, open:

```text
/_hotpot/dashboard
```

Send:

```text
Authorization: Bearer <your token>
```

The dashboard shows:

- total probe events
- unique attacking IPs
- top probe paths
- attack categories
- recognized scanner types
- top repeat offenders with score/escalation level
- top behavioral fingerprints
- recent attack activity

It is rendered server-side with no external JavaScript/CDN dependency.

### Intelligence JSON APIs

All require the same bearer token:

```text
GET /_hotpot/status
GET /_hotpot/api/intelligence
GET /_hotpot/api/attacker?ip=203.0.113.7
```

`/_hotpot/api/attacker` returns the persistent summary and most recent events for one source address.

If `HOTPOT_ADMIN_TOKEN` is unset, these administration/intelligence endpoints return `401`. This is intentional: Hotpot should not publicly expose its telemetry. `/_hotpot/health` remains public for container health checks.

## Profiles

Enabled by default:

- `wordpress`: WordPress install/login/XML-RPC/tree probes
- `secrets`: `.env`, config and credential locations
- `git`: Git/SVN metadata probes
- `php`: phpMyAdmin, PHPUnit RCE and common webshell names
- `generic`: admin/status and backup-file discovery

Profiles live under `profiles/` as TOML and support exact paths, prefixes, regexes, method restrictions, response status/content, and `deceive` or `tarpit` actions.

## Event storage and privacy

JSONL example:

```json
{"event":"deception","client_ip":"203.0.113.20","method":"GET","path":"/wp-admin/install.php","profile":"wordpress","rule":"wordpress-install","category":"wordpress-install","action":"tarpit","scanner":"WPScan","scanner_family":"wordpress-scanner","fingerprint":"b922c192e53318ca","severity":3,"escalation_level":2,"attacker_score":12}
```

Request bodies and submitted credentials are intentionally **not** stored. Hotpot is an attack telemetry system, not a credential-collection system.

## Built-in endpoints

- `GET /_hotpot/health` — public container health endpoint
- `GET /_hotpot/status` — authenticated runtime + intelligence summary
- `GET /_hotpot/dashboard` — authenticated human dashboard
- `GET /_hotpot/api/intelligence` — authenticated intelligence snapshot
- `GET /_hotpot/api/attacker?ip=...` — authenticated per-IP history

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `HOTPOT_UPSTREAM` | required | Upstream service URL |
| `HOTPOT_BIND` | `0.0.0.0` | Listen address |
| `HOTPOT_PORT` | `8080` | Listen port |
| `HOTPOT_PROFILES` | `wordpress,secrets,git,php,generic` | Enabled profiles |
| `HOTPOT_DATA_DIR` | `/data` | Persistent JSONL/SQLite directory |
| `HOTPOT_MAX_REQUEST_BODY` | `8388608` | Maximum proxied request body |
| `HOTPOT_UPSTREAM_TIMEOUT` | `60` | Upstream timeout seconds |
| `HOTPOT_TRUST_FORWARDED_FOR` | `false` | Trust X-Forwarded-For only behind a proxy you control |
| `HOTPOT_TARPIT_ENABLED` | `true` | Enable tarpit actions |
| `HOTPOT_TARPIT_MAX_CONCURRENT` | `10` | Hard concurrent tarpit cap |
| `HOTPOT_TARPIT_INITIAL_DELAY` | `1.0` | Initial delay seconds |
| `HOTPOT_TARPIT_CHUNK_DELAY` | `2.0` | Delay between streamed chunks |
| `HOTPOT_TARPIT_MAX_SECONDS` | `20` | Base tarpit lifetime |
| `HOTPOT_TARPIT_ESCALATED_MAX_SECONDS` | `60` | Hard upper bound after repeat-offender escalation |
| `HOTPOT_ADMIN_TOKEN` | unset | Enables authenticated dashboard/status/API endpoints |
| `HOTPOT_ALLOW_CIDRS` | unset | Comma-separated trusted IPs/CIDRs that bypass deception |
| `HOTPOT_RETENTION_DAYS` | `30` | SQLite/JSONL probe-event retention |
| `HOTPOT_ATTACKER_RETENTION_DAYS` | `90` | Inactive attacker-summary retention |
| `HOTPOT_HOUSEKEEPING_INTERVAL_SECONDS` | `21600` | Cleanup interval (minimum 300 seconds) |
| `HOTPOT_NOTIFY_MIN_LEVEL` | `3` | Minimum escalation level that can alert |
| `HOTPOT_NOTIFY_COOLDOWN_SECONDS` | `3600` | Repeat alert cooldown per source IP |
| `HOTPOT_NOTIFY_WEBHOOK_URL` | unset | Optional JSON webhook destination |
| `HOTPOT_NOTIFY_WEBHOOK_BEARER` | unset | Optional webhook bearer token |
| `HOTPOT_SMTP_HOST` | unset | Optional SMTP server |
| `HOTPOT_SMTP_PORT` | `587` | SMTP port |
| `HOTPOT_SMTP_STARTTLS` | `true` | Upgrade SMTP connection with STARTTLS |
| `HOTPOT_SMTP_USERNAME` | unset | Optional SMTP username |
| `HOTPOT_SMTP_PASSWORD` | unset | Optional SMTP password/app password |
| `HOTPOT_SMTP_FROM` | unset | Alert sender address |
| `HOTPOT_SMTP_TO` | unset | Comma-separated alert recipients |

## Client IPs

Hotpot supplies `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` to the protected application. Some applications must explicitly trust proxy headers before using the original client IP.

Do **not** enable `HOTPOT_TRUST_FORWARDED_FOR` when Hotpot is directly exposed to the Internet. Otherwise clients can spoof their logged source address.

## Security posture

The example Compose hardening uses a non-root image user, read-only root filesystem, `no-new-privileges`, all Linux capabilities dropped, and a small writable tmpfs. Hotpot needs no Docker socket, `NET_ADMIN`, privileged mode, host networking, SSH keys, protected application files, or application secrets.

SQLite and JSONL are the only durable writable state and belong under `/data`.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Scope

Hotpot proxies HTTP and WebSocket traffic. TLS termination remains intentionally outside Hotpot. Keeping certificate/key management out of the deception container reduces its privileges and blast radius.

## CIDR allowlist

Trusted clients can bypass all deception and tarpit rules while still passing transparently to the protected application. Configure individual addresses and/or networks as a comma-separated list:

```yaml
HOTPOT_ALLOW_CIDRS: "192.168.1.0/24,10.20.30.40,2001:db8::/32"
```

Allowlisting happens against the client IP Hotpot has determined for the request. When Hotpot is directly Internet-facing, leave `HOTPOT_TRUST_FORWARDED_FOR=false`. If Hotpot sits behind a reverse proxy you control, enable forwarded-IP trust there and ensure untrusted clients cannot connect directly to Hotpot.

The allowlist affects only attack/deception routing. It does **not** bypass bearer authentication on the Hotpot administration endpoints.

## Retention and database housekeeping

Hotpot now cleans both durable intelligence stores automatically:

- SQLite probe events: 30 days by default
- JSONL probe events: 30 days by default
- inactive attacker summaries: 90 days by default
- orphaned notification cooldown records: removed automatically
- SQLite WAL: checkpointed/truncated after cleanup
- housekeeping interval: every 6 hours by default

Cleanup also runs once at startup. Relevant settings:

```yaml
HOTPOT_RETENTION_DAYS: "30"
HOTPOT_ATTACKER_RETENTION_DAYS: "90"
HOTPOT_HOUSEKEEPING_INTERVAL_SECONDS: "21600"
```

Malformed or legacy JSONL lines without a parseable timestamp are preserved rather than deleted blindly.

Housekeeping counters appear in `/_hotpot/status` under runtime stats, including runs, deleted rows/lines, and errors.

## Escalation notifications

Notifications are off until at least one delivery channel is configured. By default Hotpot alerts when an attacker reaches escalation level 3 or 4.

Hotpot persists notification state in SQLite. Repeated level-3 activity is suppressed for the configured cooldown (default one hour), while promotion from level 3 to level 4 triggers an immediate new alert even inside that cooldown.

```yaml
HOTPOT_NOTIFY_MIN_LEVEL: "3"
HOTPOT_NOTIFY_COOLDOWN_SECONDS: "3600"
```

### Generic webhook

Configure any HTTP endpoint that accepts JSON POSTs:

```yaml
HOTPOT_NOTIFY_WEBHOOK_URL: "https://example.invalid/hotpot-alert"
HOTPOT_NOTIFY_WEBHOOK_BEARER: "optional-secret-token"
```

Payload shape:

```json
{
  "source": "hotpot",
  "event": {
    "client_ip": "203.0.113.20",
    "path": "/wp-admin/install.php",
    "scanner": "WPScan",
    "category": "wordpress-install",
    "escalation_level": 3,
    "attacker_score": 34
  }
}
```

If `HOTPOT_NOTIFY_WEBHOOK_BEARER` is set, Hotpot sends it as `Authorization: Bearer ...`.

### SMTP email

Email can be enabled independently of the webhook:

```yaml
HOTPOT_SMTP_HOST: "smtp.example.com"
HOTPOT_SMTP_PORT: "587"
HOTPOT_SMTP_STARTTLS: "true"
HOTPOT_SMTP_USERNAME: "hotpot@example.com"
HOTPOT_SMTP_PASSWORD: "use-a-secret-or-app-password"
HOTPOT_SMTP_FROM: "hotpot@example.com"
HOTPOT_SMTP_TO: "admin@example.com,security@example.com"
```

SMTP credentials are used only for delivery and are not written to attack logs or SQLite.

## Cloudflare Tunnel mode

Hotpot can sit directly behind `cloudflared` and use Cloudflare's `CF-Connecting-IP`
header as the attacker identity while retaining the local `cloudflared` address as
`proxy_ip`.

Use:

```yaml
HOTPOT_CLIENT_IP_MODE: cloudflare
HOTPOT_TRUSTED_PROXY_CIDRS: 172.30.0.0/24
```

Cloudflare mode intentionally **fails closed at startup** if no trusted proxy CIDR is
configured. Hotpot will only honor `CF-Connecting-IP` when the actual TCP peer belongs
to `HOTPOT_TRUSTED_PROXY_CIDRS`; otherwise it ignores the header and records the peer
address. This prevents a direct client from forging Cloudflare headers to poison
attacker history or influence allowlist decisions.

The recommended Docker layout is:

```text
Internet
   |
Cloudflare edge
   |
Cloudflare Tunnel
   |
cloudflared  (trusted proxy network)
   |
Hotpot       (no host port)
   |
application  (private backend network)
```

See [`compose.cloudflare.example.yml`](compose.cloudflare.example.yml) for a complete
example with a deterministic Docker subnet. In the Cloudflare dashboard, set the
published application's Service URL to `http://hotpot:8080` when `cloudflared` and
Hotpot share the same Docker network.

Probe events in this mode include both identities:

```json
{
  "client_ip": "203.0.113.42",
  "proxy_ip": "172.30.0.10",
  "client_ip_source": "cf-connecting-ip",
  "trusted_proxy": true
}
```

### Client IP modes

- `direct` — default; always use the TCP peer and ignore forwarding headers.
- `cloudflare` — trust `CF-Connecting-IP` only from configured trusted proxy CIDRs.
- `x-forwarded-for` — trust the left-most `X-Forwarded-For` address only from configured trusted proxy CIDRs.

The older `HOTPOT_TRUST_FORWARDED_FOR` switch has been replaced by these explicit modes
because blindly trusting forwarded headers is unsafe.
