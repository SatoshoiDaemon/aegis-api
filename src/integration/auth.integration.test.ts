import { buildApp } from '../app';
import { prisma } from '../shared/infra/db/prisma';
import { redis } from '../shared/infra/redis/redis';

describe('Authentication API', () => {
  const email = `integration-${Date.now()}@example.com`;
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    if (process.env.NODE_ENV !== 'test' || !process.env.DATABASE_URL?.includes('localhost')) {
      throw new Error('Integration tests require NODE_ENV=test and a localhost DATABASE_URL');
    }

    app = await buildApp();
    await prisma.auditLog.deleteMany();
    await prisma.session.deleteMany();
    await prisma.emailToken.deleteMany();
    await prisma.user.deleteMany();
    await redis.flushdb();
  });

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
});
