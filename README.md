# Aegis API

Secure authentication microservice built with TypeScript and Fastify. Aegis API provides password-based authentication, short-lived RS256 access tokens, rotating refresh tokens, session management, Redis-backed revocation, and security audit logs.

## Highlights

- Fastify REST API with OpenAPI/Swagger documentation
- Argon2 password hashing
- RS256 access tokens and hashed refresh tokens
- Refresh-token rotation with replay detection
- PostgreSQL as the source of truth for users and sessions
- Redis for rate limiting and fast session invalidation
- Correlation IDs for request tracing
- Helmet, CORS, validation, and rate limiting
- Unit tests and container-backed integration tests

## Stack

TypeScript, Node.js 20+, Fastify, Prisma, PostgreSQL 16, Redis 7, Jest, Docker Compose, and pnpm.

## Requirements

- Node.js 20 or newer
- pnpm 10 or newer
- Docker with Docker Compose

## Local setup

```bash
cp .env.example .env
pnpm install --frozen-lockfile
docker compose up -d --wait
pnpm exec prisma migrate deploy
pnpm dev
```

The service listens on `http://localhost:3333` by default.

- Health check: `GET /health`
- Swagger UI: `GET /docs`
- Auth routes: `/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, and `/auth/sessions`

## Testing

Unit tests do not require containers:

```bash
pnpm test:unit
```

Integration tests use the PostgreSQL and Redis containers:

```bash
pnpm test:containers
```

Stop and remove the local test containers and volumes with `pnpm test:containers:down`.

For a complete local quality check:

```bash
pnpm typecheck
pnpm test
pnpm build
```

## Production security

In production, set `NODE_ENV=production`, provide `PRIVATE_KEY` and `PUBLIC_KEY` through a secrets manager, and configure `CORS_ORIGINS` with an explicit comma-separated allowlist. Never commit `.env`, PEM files, access tokens, or database credentials.

Access tokens expire after 15 minutes. Refresh tokens are stored only as SHA-256 hashes and are rotated on every refresh. Reuse of a revoked refresh token revokes the user's active sessions and creates a critical audit event.

## Project structure

```text
src/
├── modules/auth/          # Authentication routes, service, repository, and schemas
├── shared/http/           # Request middleware and correlation IDs
├── shared/infra/          # Database, Redis, crypto, and logging adapters
└── integration/           # PostgreSQL/Redis-backed API tests
prisma/                    # Schema and database migrations
.github/                   # CI, security policy, and contribution templates
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security vulnerabilities must be reported privately according to [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
