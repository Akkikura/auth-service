# Security notes

- Never commit production values for `AUTH_SESSION_HASH_KEY`, `POSTGRES_URL` or Redis credentials.
- Set `APP_ENV=production`; production startup rejects implicit dependency endpoints and the example session keys shipped with this repository.
- Terminate TLS at a trusted ingress/load balancer and use TLS to PostgreSQL and Redis in production.
- Keep `/metrics` and health endpoints on trusted networks; the service does not authenticate monitoring probes.
- Configure `HTTP_TRUSTED_PROXY_CIDRS` only for proxies that overwrite forwarded headers.
- Rotating `AUTH_SESSION_HASH_KEY` revokes every active session.
- Treat leaked bearer tokens as credentials and revoke the affected Redis session immediately.
- Login/session rate limiting is fail-closed when Redis is unavailable. Registration rate limiting is intentionally fail-open; Argon2 concurrency and PostgreSQL constraints remain active.
- PostgreSQL transport/resource failures map to `503`; SQL, schema and scan defects map to `500` and must be investigated rather than retried indefinitely.
- Integration tests use isolated PostgreSQL schemas and Redis prefixes and never call `TRUNCATE` or `FLUSHDB`.
- CI runs `golangci-lint`, `govulncheck`, OpenAPI and Kubernetes validation, plus a HIGH/CRITICAL Trivy image scan. Third-party actions are pinned to full commit SHAs.
- Keep Go, PostgreSQL, Redis and direct dependencies patched.
