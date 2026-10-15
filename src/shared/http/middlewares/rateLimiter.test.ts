import { rateLimiter } from './rateLimiter';
import { redis } from '../../infra/redis/redis';
import { DomainErrors } from '../../errors/AppError';
jest.mock('../../infra/redis/redis', () => ({ redis: { eval: jest.fn() } }));
it('returns a predictable service-unavailable error on Redis failure', async () => {
  (redis.eval as jest.Mock).mockRejectedValue(new Error('Redis offline'));
  await expect(rateLimiter({ routeOptions: { url: '/auth/me', config: {} }, ip: '127.0.0.1' } as any, {} as any)).rejects.toThrow(DomainErrors.ServiceUnavailable);
});
