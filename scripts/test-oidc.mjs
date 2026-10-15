import { once } from 'node:events';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
if (process.env.NODE_ENV !== 'test' || !process.env.DATABASE_URL?.includes('localhost') || new URL(process.env.REDIS_URL).pathname !== '/15') throw new Error('Requires disposable localhost test DB and Redis /15');
const issuer = 'http://localhost:3335/oidc';
const redirect = 'http://localhost:4444/callback';
Object.assign(process.env, {
  OIDC_ENABLED: 'true', OIDC_ISSUER: issuer, OIDC_UI_URL: 'http://localhost:4444/login',
  OIDC_COOKIE_KEYS: JSON.stringify(['test-cookie-key-only-012345678901234567890']),
  OIDC_CLIENTS: JSON.stringify([{ client_id: 'test-client', redirect_uris: [redirect], response_types: ['code'], grant_types: ['authorization_code'], token_endpoint_auth_method: 'none' }]),
});
const { buildApp } = await import('../dist/app.js');
const { prisma } = await import('../dist/shared/infra/db/prisma.js');
const { redis } = await import('../dist/shared/infra/redis/redis.js');
const { OidcAdapter } = await import('../dist/modules/oidc/adapter.js');
const app = await buildApp();
const email = `integration-oidc-${Date.now()}@example.test`;
const jar = new Map();
let accountId;
async function call(method, url, payload, bearer, form = false) {
  const parsed = new URL(url, issuer);
  const response = await app.inject({ method, url: parsed.pathname + parsed.search, payload,
    headers: { host: 'localhost:3335', cookie: [...jar].map(([name, value]) => `${name}=${value}`).join('; '),
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}), ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}) },
  });
  for (const cookie of response.cookies) jar.set(cookie.name, cookie.value);
  return response;
}
try {
  if (redis.status !== 'ready') await once(redis, 'ready', { signal: AbortSignal.timeout(5000) });
  await redis.ping();
  await redis.flushdb();
  assert.equal((await call('POST', '/auth/register', { email, password: 'oidc-test-password-123' })).statusCode, 201);
  const login = await call('POST', '/auth/login', { email, password: 'oidc-test-password-123' });
  assert.equal(login.statusCode, 200);
  const token = login.json().accessToken; accountId = login.json().user.id;
  const discovery = await call('GET', '/oidc/.well-known/openid-configuration');
  assert.equal(discovery.statusCode, 200, discovery.body);
  const metadata = discovery.json();
  assert.equal(metadata.issuer, issuer);
  assert(metadata.code_challenge_methods_supported.includes('S256'));
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  async function authorize() {
    const params = new URLSearchParams({ client_id: 'test-client', redirect_uri: redirect, response_type: 'code', scope: 'openid email', code_challenge: challenge, code_challenge_method: 'S256', state: 'state-test', nonce: 'nonce-test' });
    let next = metadata.authorization_endpoint + '?' + params;
    for (let i = 0; i < 10; i++) {
      if (next.startsWith(redirect)) {
        const callback = new URL(next);
        assert.equal(callback.searchParams.get('state'), 'state-test');
        assert(callback.searchParams.has('code'), next);
        return callback.searchParams.get('code');
      }
      if (new URL(next, issuer).pathname.startsWith('/oidc/interaction/')) {
        const details = await call('GET', next, undefined, token);
        assert.equal(details.statusCode, 200, details.body);
        const consent = await call('POST', next, { consent: true }, token);
        assert.equal(consent.statusCode, 200, consent.body);
        next = consent.json().redirectTo;
      } else {
        const response = await call('GET', next);
        assert.equal(response.statusCode, 303 === response.statusCode ? 303 : 302, response.body);
        next = response.headers.location;
      }
    }
    throw new Error('Authorization did not finish');
  }
  const code = await authorize();
  const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: 'test-client', redirect_uri: redirect, code, code_verifier: verifier }).toString();
  const exchanged = await call('POST', metadata.token_endpoint, body, undefined, true);
  assert.equal(exchanged.statusCode, 200, exchanged.body);
  const tokens = exchanged.json();
  const [header, payload, signature] = tokens.id_token.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url'));
  assert.equal(claims.iss, issuer); assert.equal(claims.aud, 'test-client'); assert.equal(claims.nonce, 'nonce-test'); assert.equal(claims.sub, accountId);
  const jwks = (await call('GET', metadata.jwks_uri)).json();
  const key = jwks.keys.find(key => key.kid === JSON.parse(Buffer.from(header, 'base64url')).kid);
  assert(!key.d);
  assert(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), createPublicKey({ key, format: 'jwk' }), Buffer.from(signature, 'base64url')));
  const info = await call('GET', metadata.userinfo_endpoint, undefined, tokens.access_token);
  assert.equal(info.statusCode, 200, info.body); assert.equal(info.json().email, email);
  assert.equal((await call('POST', metadata.token_endpoint, body, undefined, true)).statusCode, 400);
  const second = await authorize();
  const invalid = new URLSearchParams({ grant_type: 'authorization_code', client_id: 'test-client', redirect_uri: redirect, code: second, code_verifier: randomBytes(32).toString('base64url') });
  assert.equal((await call('POST', metadata.token_endpoint, invalid.toString(), undefined, true)).statusCode, 400);
  // Adapter consumption is atomic even if two workers have already loaded the same artifact.
  const adapter = new OidcAdapter('AuthorizationCode');
  await adapter.upsert('atomic-test', { accountId, grantId: 'atomic-grant' }, 60);
  const attempts = await Promise.allSettled([adapter.consume('atomic-test'), adapter.consume('atomic-test')]);
  assert.equal(attempts.filter(attempt => attempt.status === 'fulfilled').length, 1);
  assert((await adapter.find('atomic-test')).consumed);
  await adapter.revokeByGrantId('atomic-grant'); assert.equal(await adapter.find('atomic-test'), undefined);
  console.log('OIDC e2e passed: discovery, login, consent, PKCE, JWT, userinfo, replay and atomic adapter');
} finally {
  if (accountId) { await prisma.oidcRecord.deleteMany({ where: { accountId } }); await prisma.user.deleteMany({ where: { id: accountId } }); }
  await app.close(); await prisma.$disconnect(); await redis.quit();
}
