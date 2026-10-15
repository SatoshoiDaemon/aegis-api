import { FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '../../infra/db/prisma';
import { DomainErrors } from '../../errors/AppError';

export async function authMiddleware(request: FastifyRequest) {
  try { await request.jwtVerify(); } catch { throw DomainErrors.InvalidToken; }
  const user = request.user as { sub?: string; sessionId?: string; tokenUse?: string };
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (user.tokenUse !== 'access' || !user.sub || !user.sessionId || !uuid.test(user.sub) || !uuid.test(user.sessionId)) throw DomainErrors.InvalidToken;
  let session;
  try { session = await prisma.session.findFirst({ where: { id: user.sessionId, userId: user.sub, revokedAt: null, expiresAt: { gt: new Date() } } }); }
  catch { throw DomainErrors.ServiceUnavailable; }
  if (!session) throw DomainErrors.TokenExpired;
}

export function requireRole(allowedRoles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.user as { sub: string; role: string };
    if (!user || !allowedRoles.includes(user.role)) return reply.status(403).send({ error: 'forbidden', message: 'Insufficient permissions' });
  };
}
