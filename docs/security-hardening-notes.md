# Dashboard hardening compatibility notes

The hardened dashboard keeps the existing browser HTTP Basic login so current deployments do not need a new identity provider or login flow. The browser receives a signed session after the Basic-authenticated page load, and the dashboard JavaScript automatically attaches the per-session CSRF token to state-changing requests.

Read-only API clients may continue using HTTP Basic authentication. Programmatic mutation clients must first obtain a session from `GET /api/session`, preserve the returned cookie, and send the returned CSRF token with the existing `X-Hotpot-Action` header.

No automatic Cloudflare approval behavior is introduced by this change.
