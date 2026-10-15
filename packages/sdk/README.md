# Aegis TypeScript SDK

Build with `pnpm sdk:build` from the repository root. Install the local package with
`npm install ./packages/sdk` or pack it for your own registry. This package is not published to npm.
Requires native fetch (Node 20+ or a modern browser); no runtime dependencies.

```ts
import { AegisClient } from '@aegis-api/sdk';
const auth = new AegisClient({ baseUrl: 'https://auth.example.com' });
await auth.login('dev@example.com', 'your password');
const user = await auth.me();
await Promise.all([auth.refresh(), auth.refresh()]); // sends ONE rotation
await auth.logout();
```

Tokens stay in memory. `setTokens()` and `onTokens` allow a host application to supply its own
storage. Coordinate refresh across tabs/processes externally; single-flight only covers one
client instance. Refresh calls are never retried automatically. On an ambiguous network failure,
require login again rather than replaying a possibly consumed token. `AegisError` exposes status,
code, correlationId and retryAfter. An in-flight refresh cannot restore tokens after logout.
