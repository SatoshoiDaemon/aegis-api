import { FastifyRequest, FastifyReply } from 'fastify';
import { createHash } from 'node:crypto';
import { redis } from '../../infra/redis/redis';
import { DomainErrors } from '../../errors/AppError';

const script = `local n = redis.call('INCR', KEYS[1]); if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end; return {n, redis.call('PTTL', KEYS[1])}`;
export async function rateLimiter(request: FastifyRequest, reply: FastifyReply) {
  const route = request.routeOptions.url || '/unmatched';
  if (['/health', '/ready', '/metrics', '/.well-known/jwks.json'].includes(route)) return;
  const config = request.routeOptions.config as { rateLimit?: { max: number; timeWindow: string } };
  const factor = Number(process.env.RATE_LIMIT_FACTOR ?? 1);
  if (!Number.isInteger(factor) || factor < 1 || factor > 10000) throw new Error('RATE_LIMIT_FACTOR must be an integer between 1 and 10000');
  const max = (config.rateLimit?.max ?? 100) * factor;
  const window = config.rateLimit?.timeWindow === '5 minutes' ? 300000 : 60000;
  const ip = createHash('sha256').update(request.ip).digest('hex');
  let result: number[];
  try { result = await redis.eval(script, 1, `rl:${route}:${ip}`, window) as number[]; }
  catch { throw DomainErrors.ServiceUnavailable; }
  if (result[0] > max) {
    reply.header('retry-after', Math.max(1, Math.ceil(result[1] / 1000)));
    return reply.status(429).send({ error: 'too_many_requests', statusCode: 429 });
  }
}
