# Dashboard action security

The Hotpot dashboard keeps HTTP Basic authentication for the initial browser login and for read-only API compatibility. After the dashboard page is authenticated, Hotpot issues a signed, expiring session cookie and a per-session CSRF token. State-changing dashboard actions require all three of the following:

- a valid signed dashboard session cookie
- the expected `X-Hotpot-Action` header
- a matching `X-Hotpot-CSRF` token

The browser dashboard adds the CSRF token automatically. Reloading the dashboard renews the session after the configured timeout. A stolen or guessed action header by itself is not sufficient to approve, dismiss, remove, reconcile, or run a system check.

Dashboard action endpoints are also rate-limited per signed session. The default is 30 state-changing requests per minute. A rejected request returns HTTP 429 with `Retry-After`.

## Session settings

```dotenv
HOTPOT_DASHBOARD_SESSION_TIMEOUT_SECONDS=3600
HOTPOT_DASHBOARD_ACTION_RATE_LIMIT_PER_MINUTE=30
HOTPOT_DASHBOARD_COOKIE_SECURE=false
```

Set `HOTPOT_DASHBOARD_COOKIE_SECURE=true` only when the dashboard is always accessed over HTTPS. A loopback/LAN HTTP deployment needs the default `false` or browsers will refuse to send the cookie.

Hotpot derives a domain-separated session signing key from `HOTPOT_DASHBOARD_TOKEN` by default. A separate signing secret is optional:

```dotenv
HOTPOT_DASHBOARD_SESSION_SECRET=REPLACE_WITH_RANDOM_SECRET
# or
HOTPOT_DASHBOARD_SESSION_SECRET_FILE=/run/secrets/dashboard_session_secret
```

The dashboard audit trail records the authenticated Basic username and signed session ID for dashboard-triggered actions. Automatic lifecycle events continue to be recorded as system events.

## File-backed secrets

The dashboard accepts file-backed forms for its sensitive credentials. When both forms are configured, `_FILE` takes precedence:

```dotenv
HOTPOT_ADMIN_TOKEN_FILE=/run/secrets/hotpot_admin_token
HOTPOT_DASHBOARD_TOKEN_FILE=/run/secrets/dashboard_token
HOTPOT_CLOUDFLARE_API_TOKEN_FILE=/run/secrets/cloudflare_api_token
```

The existing direct environment variables remain supported:

```dotenv
HOTPOT_ADMIN_TOKEN=...
HOTPOT_DASHBOARD_TOKEN=...
HOTPOT_CLOUDFLARE_API_TOKEN=...
```

File-backed values are read at dashboard startup. The hardened dashboard entrypoint only injects them temporarily while legacy constructors initialize and then restores the process environment. This keeps the actual credential value out of the container configuration when the deployment supplies only the `_FILE` variable.

The secret file must be readable by the dashboard container user. On Docker/Compose, mount the file read-only and avoid placing the secret contents in the Compose file itself.

## API compatibility

Read-only endpoints continue to accept the existing HTTP Basic credentials. `/api/session` can be used by an authenticated client to obtain/renew a signed dashboard session and CSRF token. Mutation endpoints require the signed session and CSRF token in addition to Basic-compatible dashboard authentication behavior.
