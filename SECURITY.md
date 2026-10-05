# Security Policy

Hotpot intentionally receives hostile HTTP traffic. Treat it as an Internet-facing security component and keep the container isolated from sensitive host resources.

## Reporting a vulnerability

Please do not publish exploit details in a public issue before a fix is available. Use GitHub's private vulnerability reporting feature if it is enabled for the repository, or contact the repository owner privately.

## Deployment guidance

- Do not mount the Docker socket.
- Do not run Hotpot privileged or with `NET_ADMIN`.
- Keep the root filesystem read-only where practical.
- Persist only `/data`.
- Do not expose the upstream application directly on the same host port.
- Keep `HOTPOT_TRUST_FORWARDED_FOR=false` unless Hotpot is behind a trusted reverse proxy and direct access is blocked.
- Configure `HOTPOT_ADMIN_TOKEN` before exposing dashboard or intelligence endpoints.
- Keep notification credentials in environment variables or Docker secrets, never committed to Git.
