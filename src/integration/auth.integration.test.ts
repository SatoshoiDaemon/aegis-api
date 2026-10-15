import { IdentityService, IdentityMessage } from '../modules/auth/identity.service';
import { createPublicKey, verify } from 'node:crypto';
import { buildApp } from '../app';
import { prisma } from '../shared/infra/db/prisma';
import { redis } from '../shared/infra/redis/redis';

describe('Authentication API', () => {
  const email = `integration-${Date.now()}@example.com`;
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    if (process.env.NODE_ENV !== 'test' || !process.env.DATABASE_URL?.includes('localhost') || new URL(process.env.REDIS_URL || 'redis://localhost').pathname !== '/15') {
      throw new Error('Integration tests require NODE_ENV=test, a localhost DATABASE_URL and Redis database /15');
    }

    app = await buildApp();
    await prisma.user.deleteMany({ where: { email: { startsWith: 'integration-' } } });
    await redis.flushdb();
  });

  beforeEach(async () => { await redis.flushdb(); });

  afterAll(async () => {
    if (app) await app.close();
    await prisma.$disconnect();
    await redis.quit();
  });

  it('returns a health response and a correlation id', async () => {
    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(200);
    expect(response.headers['x-correlation-id']).toEqual(expect.any(String));
    expect(response.json()).toEqual(expect.objectContaining({ status: 'ok' }));
  });

  it('registers, logs in, and never exposes refresh token hashes', async () => {
    const register = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: 'correct horse battery staple' },
    });
    expect(register.statusCode).toBe(201);

    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: 'correct horse battery staple' },
    });
    expect(login.statusCode).toBe(200);
    const tokens = login.json();
    expect(tokens.accessToken).toEqual(expect.any(String));
    expect(tokens.refreshToken).toEqual(expect.any(String));

    const sessions = await app.inject({
      method: 'GET',
      url: '/auth/sessions',
      headers: { authorization: `Bearer ${tokens.accessToken}` },
    });
    expect(sessions.statusCode).toBe(200);
    expect(sessions.json().sessions[0]).not.toHaveProperty('refreshTokenHash');
  });

  it('rotates refresh tokens and revokes the entire session family on replay', async () => {
    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: 'correct horse battery staple' },
    });
    const original = login.json();

    const refresh = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: original.refreshToken },
    });
    expect(refresh.statusCode).toBe(200);
    const rotated = refresh.json();
    expect(rotated.refreshToken).not.toBe(original.refreshToken);

    const replay = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: original.refreshToken },
    });
    expect(replay.statusCode).toBe(401);
    expect(replay.json().error).toBe('session_reuse_detected');

    const revokedAccess = await app.inject({
      method: 'GET',
      url: '/auth/sessions',
      headers: { authorization: `Bearer ${rotated.accessToken}` },
    });
    expect(revokedAccess.statusCode).toBe(401);
  });

  async function login() {
    const response = await app.inject({ method: 'POST', url: '/auth/login', payload: { email, password: 'correct horse battery staple' } });
    expect(response.statusCode).toBe(200); return response.json();
  }

  it('serializes simultaneous refreshes: one winner, replay revokes every descendant', async () => {
    const original = await login();
    const responses = await Promise.all(Array.from({ length: 12 }, () => app.inject({ method: 'POST', url: '/auth/refresh', payload: { refreshToken: original.refreshToken } })));
    expect(responses.filter(response => response.statusCode === 200)).toHaveLength(1);
    expect(responses.filter(response => response.statusCode === 401)).toHaveLength(11);
    const user = await prisma.user.findUniqueOrThrow({ where: { email } });
    expect(await prisma.session.count({ where: { userId: user.id, revokedAt: null } })).toBe(0);
    const winner = responses.find(response => response.statusCode === 200)!.json();
    const me = await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: `Bearer ${winner.accessToken}` } });
    expect(me.statusCode).toBe(401);
  });

  it('rejects a revoked access token even after Redis loses all keys', async () => {
    const tokens = await login();
    const logout = await app.inject({ method: 'POST', url: '/auth/logout', headers: { authorization: `Bearer ${tokens.accessToken}` } });
    expect(logout.statusCode).toBe(200);
    await redis.flushdb();
    const me = await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: `Bearer ${tokens.accessToken}` } });
    expect(me.statusCode).toBe(401);
  });

  it('publishes JWKS, uses kid/issuer/audience and returns only public profile fields', async () => {
    const tokens = await login();
    const jwks = (await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();
    const [header, payload, signature] = tokens.accessToken.split('.');
    expect(JSON.parse(Buffer.from(header, 'base64url').toString()).kid).toBe(jwks.keys[0].kid);
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    expect(claims.iss).toBe('http://localhost:3333'); expect(claims.aud).toBe('aegis-api');
    expect(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), createPublicKey({ key: jwks.keys[0], format: 'jwk' }), Buffer.from(signature, 'base64url'))).toBe(true);
    expect(jwks.keys[0]).not.toHaveProperty('d');
    const me = await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: `Bearer ${tokens.accessToken}` } });
    expect(me.statusCode).toBe(200); expect(me.headers['cache-control']).toBe('no-store');
    expect(me.json()).toEqual(expect.objectContaining({ email, isVerified: false }));
    expect(me.json()).not.toHaveProperty('passwordHash');
  });


  it('rejects wrong audiences, issuers and access-token types', async () => {
    const tokens = await login();
    const claims = app.jwt.decode(tokens.accessToken) as Record<string, unknown>;
    for (const overrides of [{ aud: 'another-service' }, { iss: 'https://other-issuer.example' }, { tokenUse: 'id' }, { sessionId: undefined }]) {
      const { aud, iss, ...payloadOverrides } = overrides as Record<string, unknown>;
      const token = app.jwt.sign({ ...claims, ...payloadOverrides }, { ...(aud ? { aud: String(aud) } : {}), ...(iss ? { iss: String(iss) } : {}) });
      const response = await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: `Bearer ${token}` } });
      expect(response.statusCode).toBe(401);
    }
  });

  it('documents request bodies and protects the metrics endpoint', async () => {
    const spec = (await app.inject({ method: 'GET', url: '/docs/json' })).json();
    expect(spec.paths['/auth/login'].post.requestBody).toBeDefined();
    expect((await app.inject({ method: 'GET', url: '/metrics' })).statusCode).toBe(404);
    process.env.METRICS_TOKEN = 'integration-metrics';
    try {
      const response = await app.inject({ method: 'GET', url: '/metrics', headers: { authorization: 'Bearer integration-metrics' } });
      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('aegis_http_requests_total');
      expect(response.body).not.toContain(email);
    } finally { delete process.env.METRICS_TOKEN; }
  });

  it('verifies email once and rejects expired or reused tokens', async () => {
    let message: IdentityMessage | undefined;
    const service = new IdentityService(async value => { message = value; });
    await service.request(email, 'VERIFY_EMAIL');
    expect(message).toBeDefined();
    const stored = await prisma.emailToken.findFirstOrThrow({ where: { type: 'VERIFY_EMAIL', user: { email } } });
    expect(stored.tokenHash).not.toBe(message!.token);
    await prisma.emailToken.update({ where: { id: stored.id }, data: { expiresAt: new Date(0) } });
    await expect(service.consume(message!.token, 'VERIFY_EMAIL')).rejects.toThrow();
    await prisma.emailToken.update({ where: { id: stored.id }, data: { expiresAt: new Date(Date.now() + 60000) } });
    await service.consume(message!.token, 'VERIFY_EMAIL');
    await expect(service.consume(message!.token, 'VERIFY_EMAIL')).rejects.toThrow();
    expect((await prisma.user.findUniqueOrThrow({ where: { email } })).isVerified).toBe(true);
  });

  it('does not retain an undelivered identity token', async () => {
    const user = await prisma.user.create({ data: { email: `integration-delivery-${Date.now()}@example.test`, passwordHash: 'unused' } });
    const service = new IdentityService(async () => { throw new Error('offline'); });
    await service.request(user.email, 'RESET_PASSWORD');
    expect(await prisma.emailToken.count({ where: { userId: user.id } })).toBe(0);
  });

  it('consumes a password-reset token only once under concurrency and revokes sessions', async () => {
    const tokens = await login();
    let message: IdentityMessage | undefined;
    const service = new IdentityService(async value => { message = value; });
    await service.request(email, 'RESET_PASSWORD');
    const results = await Promise.allSettled(Array.from({ length: 3 }, () => service.consume(message!.token, 'RESET_PASSWORD', 'new correct horse battery staple')));
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    const me = await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: `Bearer ${tokens.accessToken}` } });
    expect(me.statusCode).toBe(401);
    const old = await app.inject({ method: 'POST', url: '/auth/login', payload: { email, password: 'correct horse battery staple' } });
    expect(old.statusCode).toBe(401);
    const next = await app.inject({ method: 'POST', url: '/auth/login', payload: { email, password: 'new correct horse battery staple' } });
    expect(next.statusCode).toBe(200);
  });

  it('keeps liveness available and rejects authentication predictably during Redis outage', async () => {
    await new Promise<void>(resolve => { redis.once('end', resolve); redis.disconnect(); });
    try {
      const health = await app.inject({ method: 'GET', url: '/health' });
      expect(health.statusCode).toBe(200);
      const ready = await app.inject({ method: 'GET', url: '/ready' });
      expect(ready.statusCode).toBe(503);
      const login = await app.inject({ method: 'POST', url: '/auth/login', payload: { email, password: 'irrelevant' } });
      expect(login.statusCode).toBe(503); expect(login.json().error).toBe('service_unavailable');
    } finally { await redis.connect(); }
  });
});
