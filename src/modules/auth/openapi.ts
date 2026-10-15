import { FastifyInstance } from 'fastify';
const email = { type: 'string', format: 'email', maxLength: 254 };
const password = { type: 'string', minLength: 8, maxLength: 128 };
const token = { type: 'string', pattern: '^[a-f0-9]{64}$' };
const bodies: Record<string, { properties: Record<string, unknown>; required: string[] }> = {
  '/register': { properties: { email, password }, required: ['email', 'password'] },
  '/login': { properties: { email, password: { ...password, minLength: 1 } }, required: ['email', 'password'] },
  '/refresh': { properties: { refreshToken: { type: 'string', pattern: '^[a-f0-9]{80}$' } }, required: ['refreshToken'] },
  '/forgot-password': { properties: { email }, required: ['email'] },
  '/reset-password': { properties: { token, newPassword: password }, required: ['token', 'newPassword'] },
  '/verify-email': { properties: { token }, required: ['token'] },
};
export function describeAuthRoutes(app: FastifyInstance) {
  app.addHook('onRoute', route => {
    if (!route.url.startsWith('/auth/')) return;
    const name = route.url.slice('/auth'.length);
    const body = bodies[name];
    route.schema = {
      tags: ['Authentication'],
      ...(body ? { body: { type: 'object', additionalProperties: false, ...body } } : {}),
      ...(['/me', '/sessions', '/sessions/:id', '/logout', '/verification-email'].includes(name) ? { security: [{ bearerAuth: [] }] } : {}),
      ...(name === '/sessions/:id' ? { params: { type: 'object', required: ['id'], properties: { id: { type: 'string', format: 'uuid' } } } } : {}),
      ...route.schema,
    };
  });
}
