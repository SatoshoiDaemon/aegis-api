import { AuthService } from './auth.service';
import { AuthRepository } from './auth.repository';
import { DomainErrors } from '../../shared/errors/AppError';
jest.mock('./auth.repository');
jest.mock('../../shared/infra/redis/redis', () => ({ redis: { set: jest.fn().mockResolvedValue('OK') } }));
jest.mock('../../shared/infra/db/prisma', () => ({ prisma: {} }));

describe('AuthService', () => {
  let service: AuthService;
  let repository: jest.Mocked<AuthRepository>;
  beforeEach(() => {
    repository = new AuthRepository() as jest.Mocked<AuthRepository>;
    repository.findActiveSessionsByUserId.mockResolvedValue([]);
    service = new AuthService(repository);
  });
  it('audits invalid login', async () => {
    repository.findUserByEmail.mockResolvedValue(null);
    await expect(service.login({ email: 'fake@example.com', password: '123' })).rejects.toThrow(DomainErrors.InvalidCredentials);
    expect(repository.logAudit).toHaveBeenCalledWith('LOGIN_FAIL', undefined, undefined, null, { email: 'fake@example.com' }, 'WARN', null);
  });
  it.each([['invalid', DomainErrors.InvalidToken], ['expired', DomainErrors.TokenExpired]] as const)('rejects %s refresh', async (kind, error) => {
    repository.rotateSession.mockResolvedValue({ kind });
    await expect(service.refresh('plain')).rejects.toThrow(error);
  });
  it('reports committed replay revocation', async () => {
    repository.rotateSession.mockResolvedValue({ kind: 'reuse', session: { id: 's1', userId: 'u1', ip: 'original' } } as any);
    await expect(service.refresh('plain', 'remote')).rejects.toThrow(DomainErrors.SessionReuseDetected);
    expect(repository.logAudit).toHaveBeenCalledWith('TOKEN_REUSE_DETECTED', 'remote', undefined, 'u1', { sessionId: 's1', originalIp: 'original' }, 'CRITICAL', null);
  });
  it('returns a new token only after the transaction commits', async () => {
    repository.rotateSession.mockResolvedValue({ kind: 'rotated', session: { id: 'new' }, user: { id: 'u1' }, oldSessionId: 'old' } as any);
    const result = await service.refresh('original');
    expect(result.refreshTokenPlain).toMatch(/^[a-f0-9]{80}$/);
    expect(repository.rotateSession).toHaveBeenCalledWith(expect.stringMatching(/^[a-f0-9]{64}$/), expect.stringMatching(/^[a-f0-9]{64}$/), undefined, undefined);
  });
  it('does not swallow transaction failures', async () => {
    repository.rotateSession.mockRejectedValue(new Error('database offline'));
    await expect(service.refresh('plain')).rejects.toThrow('database offline');
  });
});
