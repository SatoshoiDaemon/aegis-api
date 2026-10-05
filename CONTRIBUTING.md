# Contributing to Aegis API

Thank you for contributing. Keep changes focused, explain security-sensitive decisions, and preserve backward compatibility for the HTTP API whenever possible.

## Development workflow

1. Fork the repository and create a branch from `main`.
2. Copy `.env.example` to `.env` and start the local PostgreSQL and Redis containers.
3. Install dependencies with `pnpm install --frozen-lockfile`.
4. Run `pnpm typecheck`, `pnpm test`, and `pnpm build` before opening a pull request.
5. Update tests and documentation when behavior changes.

## Commit and pull request guidance

Use concise imperative commit messages such as `feat: add session listing`. Pull requests should describe the problem, the solution, test evidence, migration impact, and any security implications.

Do not include secrets, real user data, database dumps, generated keys, `node_modules`, or build output.

## Database changes

Schema changes must include a Prisma migration. Explain destructive or backward-incompatible changes in the pull request and verify the migration against a clean PostgreSQL container.
