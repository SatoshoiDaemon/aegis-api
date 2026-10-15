import { authMiddleware } from './authMiddleware';
import { DomainErrors } from '../../errors/AppError';
import { prisma } from '../../infra/db/prisma';
jest.mock('../../infra/db/prisma', () => ({ prisma: { session: { findFirst: jest.fn() } } }));
const id = '00000000-0000-4000-8000-000000000001';
describe('authoritative session validation', () => {
  const request = () => ({ jwtVerify: jest.fn().mockResolvedValue(undefined), user: { sub: id, sessionId: id, tokenUse: 'access' } });
  it('rejects cryptographically valid tokens for revoked sessions', async () => {
    (prisma.session.findFirst as jest.Mock).mockResolvedValue(null);
    await expect(authMiddleware(request() as any)).rejects.toThrow(DomainErrors.TokenExpired);
  });
  it('fails closed with 503 when the session store cannot be checked', async () => {
    (prisma.session.findFirst as jest.Mock).mockRejectedValue(new Error('offline'));
    await expect(authMiddleware(request() as any)).rejects.toThrow(DomainErrors.ServiceUnavailable);
  });
  it('rejects tokens without session binding', async () => {
    const req = request(); delete (req.user as any).sessionId;
    await expect(authMiddleware(req as any)).rejects.toThrow(DomainErrors.InvalidToken);
  });
});
