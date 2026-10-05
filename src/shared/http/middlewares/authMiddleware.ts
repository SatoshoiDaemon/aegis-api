import { FastifyRequest, FastifyReply } from 'fastify';
import { redis } from '../../infra/redis/redis';
import { DomainErrors } from '../../errors/AppError';

export async function authMiddleware(request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
    const user = request.user as { sub: string; role: string; sessionId?: string };
    
    // Quick-check via Redis for invalidated sessions (Inconsistency mitigation)
    if (user.sessionId) {
      const isRevoked = await redis.get(`revoked:${user.sessionId}`);
      if (isRevoked) {
        throw DomainErrors.TokenExpired;
      }
    }
  } catch (err: any) {
    if (err.name === 'AppError') throw err;
    reply.status(401).send({ error: 'invalid_token', message: 'Invalid or missing token' });
  }
}

export function requireRole(allowedRoles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.user as { sub: string; role: string };
    if (!user || !allowedRoles.includes(user.role)) {
      return reply.status(403).send({ error: 'forbidden', message: 'Insufficient permissions' });
    }
  };
}
