# Aegis API

Self-hosted authentication API built with TypeScript, Fastify, PostgreSQL and Redis.
Provides password authentication, RS256 JWTs, rotating refresh tokens, revocable sessions,
password recovery, email verification, a TypeScript client and optional OAuth2/OpenID Connect.

## Start locally

Requires Node.js 22.12+ (Node 24 recommended), pnpm 10.33, PostgreSQL 16 and Redis 7.

```sh
cp .env.example .env
corepack enable
pnpm install --frozen-lockfile
pnpm exec prisma generate
docker compose up -d --wait
pnpm exec prisma migrate deploy
pnpm dev
```

The API listens on `http://localhost:3333`. Interactive request schemas are available at `/docs`.
Configure the email delivery webhook before enabling recovery and verification requests.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth/register` | Register `{email, password}` |
| POST | `/auth/login` | Get `{accessToken, refreshToken, user}` |
| POST | `/auth/refresh` | Rotate `{refreshToken}` |
| GET | `/auth/me` | Current profile; requires bearer access token |
| POST | `/auth/logout` | Revoke current session |
| GET | `/auth/sessions` | List active sessions without token hashes |
| DELETE | `/auth/sessions/:id` | Revoke one of the user's sessions |
| DELETE | `/auth/sessions` | Revoke all REST sessions |
| POST | `/auth/forgot-password` | Request password reset with `{email}` |
| POST | `/auth/reset-password` | Consume `{token, newPassword}`; revoke sessions |
| POST | `/auth/verification-email` | Request verification for the authenticated account |
| POST | `/auth/verify-email` | Consume `{token}` |
| GET | `/.well-known/jwks.json` | Public RS256 signing key |
| GET | `/health` | Process liveness |
| GET | `/ready` | PostgreSQL and Redis readiness |
| GET | `/metrics` | Prometheus counters and latency histogram; requires `METRICS_TOKEN` |

Session routes, logout and profile require `Authorization: Bearer <accessToken>`.
Auth responses use `Cache-Control: no-store`. Errors include an `error` code, and every
request returns `x-correlation-id`. Dependency failures return 503; rate limits return 429
and `Retry-After`. Invalid credentials/tokens return 401; malformed requests return 400.

## Token and failure semantics

- Access JWT lifetime: 15 minutes. Validate RS256, `iss`, `aud`, `exp` and `kid` using JWKS.
  Set `JWT_ISSUER` and `JWT_AUDIENCE` consistently across all instances and consumers.
- JWTs contain `sub`, `role`, `sessionId` and `tokenUse: access`. Previous JWTs without the
  new issuer/audience/token-use claims must be replaced by logging in after this upgrade.
- Refresh lifetime: 30 days from login, preserved through rotations. Only SHA-256 hashes
  are stored. Each successful refresh revokes its predecessor and creates one successor
  in a single PostgreSQL transaction.
- Session writers serialize on the user row. Logout/revocation follows a session family
  across rotations, including a successor created before a delayed logout commits. Replaying a revoked refresh token revokes
  **all of that user's REST sessions**, including the winning concurrent refresh.
  Two concurrent refreshes are therefore a security event, not two successful logins.
  Clients must serialize rotation; do not blindly retry a refresh after a network timeout.
- Every protected REST request checks the PostgreSQL session. Lost Redis keys, Redis
  restarts and failed blacklist writes cannot resurrect a revoked session.
- Redis supplies shared atomic rate limits. When unavailable, auth/protocol requests fail
  closed with 503. No local per-process fallback changes the policy. `/health` and JWKS
  stay available; `/ready` returns 503. A rejected logout must be retried after recovery.
- PostgreSQL connection/statement timeouts are bounded. Unavailable session checks fail
  closed. Audit writes are best effort and emit an error log if persistence fails.
- Public JWT validation in another service is offline and cannot observe immediate session
  revocation. Proxy through Aegis for immediate enforcement, or accept the 15-minute JWT
  lifetime in that service. Do not treat JWKS validation as an online session check.

## Email delivery

Set `MAIL_WEBHOOK_URL` and `MAIL_WEBHOOK_TOKEN`. The webhook must accept a JSON POST with
`Authorization: Bearer <MAIL_WEBHOOK_TOKEN>` and respond with 2xx after accepting delivery:

```json
{ "to": "dev@example.com", "type": "RESET_PASSWORD", "token": "one-time-token", "expiresAt": "2026-10-15T20:00:00.000Z" }
```

`type` is `RESET_PASSWORD` or `VERIFY_EMAIL`. Your mail adapter constructs a frontend link
and sends it through your provider. The frontend submits the token to the matching POST
endpoint; merely opening a link never consumes a token. Use HTTPS in production. Do not
log the webhook body or put tokens in analytics. Plaintext tokens are never returned by
the API or persisted in PostgreSQL.

Reset tokens expire in 30 minutes; verification tokens in 24 hours. Issuance is limited
per account to once a minute, in addition to shared IP limits. Issuing another token
invalidates the previous one. Delivery failure deletes the undelivered token and emits
`identity_delivery_failed`. The public reset request remains 202 for unknown addresses
and delivery failures; operators should alert on that event. Missing delivery configuration
returns 503 uniformly. Token consumption, password update and session revocation commit
atomically; expired/replayed tokens fail. Password reset also removes persisted OIDC state
for the account. Successful password reset does not automatically log the user in.

## TypeScript SDK

See [packages/sdk/README.md](packages/sdk/README.md). Build with `pnpm sdk:build`.
The package has no runtime dependencies and uses native fetch. It is included in the
repository and has not been published to npm. It keeps tokens in memory and coalesces
concurrent refresh calls within one client instance.

## OAuth2 / OIDC

Opt-in integration using `oidc-provider` with a PostgreSQL adapter, Authorization Code,
mandatory PKCE, explicit client redirect URIs, discovery, userinfo and revocation.
Disabled by default. See [docs/oidc.md](docs/oidc.md) for configuration and the login/consent
UI contract. This deployment has not undergone OpenID conformance certification.

## Operations and tests

```sh
pnpm typecheck
pnpm lint
pnpm test                 # deterministic unit tests; no services
pnpm sdk:build
pnpm build
pnpm test:containers      # local disposable PostgreSQL + Redis /15
# With test services running:
NODE_ENV=test DATABASE_URL=postgresql://root:password@localhost:5432/auth_db REDIS_URL=redis://localhost:6379/15 pnpm test:oidc
```

Integration tests require a localhost database, `NODE_ENV=test` and the reserved Redis
DB 15. They flush that Redis database and remove users whose email starts `integration-`.
Use disposable infrastructure. `pnpm test:containers:down` removes compose volumes.

CI runs migrations, types, lint, unit/integration tests, SDK/server builds, an OIDC
end-to-end flow and disposable load smoke tests. Latency/status reports are attached to
the Actions run as `load-smoke-results`. See [docs/operations.md](docs/operations.md) for
load profiles, observability, retention and deployment details.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [LICENSE](LICENSE).
