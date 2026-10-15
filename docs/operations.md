# Running Aegis

## Deploy and upgrade

- Use Node 24, PostgreSQL 16 and Redis 7. Apply `pnpm exec prisma migrate deploy` once
  before starting the new release. Generate Prisma client during the build.
- Configure production PEM keys, HTTPS `JWT_ISSUER`, `JWT_AUDIENCE`, explicit CORS origins,
  database/Redis URLs and the mail adapter. Production startup rejects missing/mismatched
  RSA keys and invalid issuer settings. Never generate production keys per replica.
- The uniqueness migration rejects duplicate refresh/email token hashes. Investigate
  duplicates before migrating; do not silently delete active sessions.
- This release normalizes newly submitted emails to lowercase. Normalize legacy mixed-case
  addresses and resolve case-only duplicates before rollout.
- Clients must log in again after upgrading because JWT issuer/audience/token-use claims
  are now mandatory. Refresh rotation invalidates the predecessor's REST access token too.
- Reuse detection deliberately revokes every REST session for that user, including a
  successful concurrent rotation. Use the SDK's single-flight refresh and coordinate tabs.
- Pin identical keys/configuration across replicas. JWKS `kid` is the SHA-256 JWK thumbprint.
  This version exposes one active signing key: replacing it invalidates older JWTs at
  Aegis. Coordinate key replacement and consumer caches (JWKS max-age: 300 seconds).
- JWT validation by external services is offline. Instant revocation requires an online
  session check through Aegis; signature verification alone does not provide that.
- Place `/metrics` behind an internal ingress and set `METRICS_TOKEN`. `/health` is liveness,
  `/ready` is readiness. An unhealthy dependency must remove the instance from service.
- `DB_POOL_MAX` defaults to 20 per replica. Keep the total below PostgreSQL's connection
  budget. Connection timeout is 2 seconds; statement/query timeout is 5 seconds. Redis
  command and connection timeouts are 1 second, with bounded per-command retries and
  offline queuing disabled. Auth requests fail closed on Redis errors.
- TLS terminates at your reverse proxy. Fastify does not trust arbitrary forwarded IPs.
  Rate limits use the socket peer IP: configure a trusted ingress/client-IP policy before
  sharing a public proxy, or the proxy's users will share limits. Do not enable unrestricted
  `trustProxy` merely to improve load-test numbers.

## Observe

`GET /metrics` with `Authorization: Bearer <METRICS_TOKEN>` exposes
`aegis_http_requests_total` and `aegis_http_request_duration_seconds` (histogram), labelled
by method, route template and HTTP status. No email, session ID or raw URL is a label.
Compute failure rates by 401/429/503 and p95/p99 by route. Counters reset per process.

JSON logs include correlation ID, route, status and duration. Token/credential headers
are redacted and query strings are omitted by the request serializer. Audit logs persist
login outcomes, refreshes, replay detection, logout and password reset. Monitor
`identity_delivery_failed`, audit-write errors, 503s and rising latency. Audit persistence
is best effort, so logs and database events are complementary, not a durable event queue.

## Load testing

Run only against disposable local/staging infrastructure and a separate database:

```sh
# Start the server for the benchmark with RATE_LIMIT_FACTOR=1000.
LOAD_ACK=disposable-environment LOAD_MODE=me LOAD_CONCURRENCY=4 LOAD_ITERATIONS=25 pnpm test:load
LOAD_ACK=disposable-environment LOAD_MODE=login LOAD_CONCURRENCY=4 LOAD_ITERATIONS=10 pnpm test:load
LOAD_ACK=disposable-environment LOAD_MODE=refresh LOAD_CONCURRENCY=4 LOAD_ITERATIONS=25 pnpm test:load
```

Set `LOAD_BASE_URL` for a staging target. Each worker provisions a separate account and
session. Refresh chains are sequential per worker; cross-worker races are tested separately
in the integration suite. Reports contain HTTP statuses, p50/p95/p99 latency and throughput.
Errors/rate limiting fail the command; an unavailable target fails provisioning immediately.
Accounts/sessions remain in the disposable database for inspection. Reset that infrastructure
after the run. The tool does not silently weaken rate limits.

`RATE_LIMIT_FACTOR` defaults to 1. Raising it explicitly multiplies all configured limits;
use it only for controlled benchmarks with separate ingress protection, then restore 1.
CI runs a short 4-worker smoke profile and uploads JSON reports. It is a regression signal,
not a production capacity estimate. For capacity planning, increase concurrency gradually
on representative hardware, run longer steady-state tests and compare Argon2 CPU/RAM,
PostgreSQL locks/pool saturation, Redis latency and API p95/p99. Record hardware, replica
count, pool settings and whether rate limiting was included when reporting results.

## Retention

After `pnpm build`, schedule `node scripts/cleanup.mjs` externally (for example daily).
It deletes expired sessions, email/OIDC artifacts and audit logs older than
`AUDIT_RETENTION_DAYS` (default 90). Do not delete revoked sessions before their absolute
expiry: they are replay evidence. Cleanup is explicit and does not run during normal
requests. Back up PostgreSQL and signing/cookie keys, and test restoration in staging.
