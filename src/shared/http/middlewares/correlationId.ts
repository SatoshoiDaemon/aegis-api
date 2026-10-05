import { FastifyRequest, FastifyReply } from 'fastify';
import { randomUUID } from 'crypto';

export async function correlationIdMiddleware(request: FastifyRequest, reply: FastifyReply) {
  const providedId = request.headers['x-correlation-id'];
  const correlationId = typeof providedId === 'string' && /^[a-zA-Z0-9._:-]{1,128}$/.test(providedId)
    ? providedId
    : randomUUID();
  request.requestContext.set('correlationId', correlationId);
  reply.header('x-correlation-id', correlationId);
}
