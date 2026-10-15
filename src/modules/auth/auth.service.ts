import { AuthRepository } from './auth.repository';
import { RegisterInput, LoginInput } from './auth.schemas';
import * as argon2 from 'argon2';
import crypto from 'crypto';
import { DomainErrors } from '../../shared/errors/AppError';
import { AuditAction } from '@prisma/client';
import { requestContext } from '@fastify/request-context';
import { prisma } from '../../shared/infra/db/prisma';

export class AuthService {
  constructor(private readonly repository: AuthRepository) {}

  private getCorrelationId() {
    return requestContext.get('correlationId') ?? null;
  }

  private generateRefreshToken() {
    return crypto.randomBytes(40).toString('hex');
  }

  private hashToken(token: string) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async register(data: RegisterInput, ip?: string, userAgent?: string) {
    const existingUser = await this.repository.findUserByEmail(data.email);
    if (existingUser) {
      throw DomainErrors.UserAlreadyExists;
    }

    const passwordHash = await argon2.hash(data.password);
    const user = await this.repository.createUser({
      email: data.email,
      passwordHash,
    });

    this.repository.logAudit(AuditAction.LOGIN_SUCCESS, ip, userAgent, user.id, { event: 'registration_and_login' }, 'INFO', this.getCorrelationId());

    return user;
  }

  async login(data: LoginInput, ip?: string, userAgent?: string) {
    const user = await this.repository.findUserByEmail(data.email);
    if (!user) {
      this.repository.logAudit(AuditAction.LOGIN_FAIL, ip, userAgent, null, { email: data.email }, 'WARN', this.getCorrelationId());
      throw DomainErrors.InvalidCredentials;
    }

    const validPassword = await argon2.verify(user.passwordHash, data.password);
    if (!validPassword) {
      this.repository.logAudit(AuditAction.LOGIN_FAIL, ip, userAgent, user.id, { reason: 'invalid_password' }, 'WARN', this.getCorrelationId());
      throw DomainErrors.InvalidCredentials;
    }

    const refreshTokenPlain = this.generateRefreshToken();
    const refreshTokenHash = this.hashToken(refreshTokenPlain);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30); // 30 days

    const session = await this.repository.createSession({
      userId: user.id,
      refreshTokenHash,
      ip,
      userAgent,
      expiresAt,
    }, user.passwordHash);

    this.repository.logAudit(AuditAction.LOGIN_SUCCESS, ip, userAgent, user.id, { sessionId: session.id }, 'INFO', this.getCorrelationId());

    return { user, session, refreshTokenPlain };
  }

  async refresh(refreshTokenPlain: string, ip?: string, userAgent?: string) {
    const next = this.generateRefreshToken();
    const result = await this.repository.rotateSession(this.hashToken(refreshTokenPlain), this.hashToken(next), ip, userAgent);
    if (result.kind === 'invalid') throw DomainErrors.InvalidToken;
    if (result.kind === 'expired') throw DomainErrors.TokenExpired;
    if (result.kind === 'reuse') {
      this.repository.logAudit(AuditAction.TOKEN_REUSE_DETECTED, ip, userAgent, result.session.userId,
        { sessionId: result.session.id, originalIp: result.session.ip }, 'CRITICAL', this.getCorrelationId());
      throw DomainErrors.SessionReuseDetected;
    }
    this.repository.logAudit(AuditAction.TOKEN_REFRESH, ip, userAgent, result.user.id,
      { newSessionId: result.session.id, oldSessionId: result.oldSessionId }, 'INFO', this.getCorrelationId());
    return { user: result.user, session: result.session, refreshTokenPlain: next };
  }

  async logout(sessionId: string, userId: string, ip?: string, userAgent?: string) {
    await this.repository.revokeSession(sessionId);
    this.repository.logAudit(AuditAction.LOGOUT, ip, userAgent, userId, { sessionId }, 'INFO', this.getCorrelationId());
  }

  // Session Management
  async listUserSessions(userId: string) {
    return prisma.session.findMany({
      where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
      select: {
        id: true,
        userAgent: true,
        ip: true,
        expiresAt: true,
        createdAt: true,
        revokedAt: true,
      }
    });
  }

  async revokeSpecificSession(sessionId: string, userId: string, ip?: string, userAgent?: string) {
    const session = await prisma.session.findFirst({ where: { id: sessionId, userId } });
    if (!session) throw DomainErrors.SessionNotFound;

    await this.repository.revokeSession(sessionId);
    this.repository.logAudit(AuditAction.LOGOUT, ip, userAgent, userId, { sessionId, explicitRevoke: true }, 'INFO', this.getCorrelationId());
  }

  async revokeAllSessions(userId: string, ip?: string, userAgent?: string) {
    await this.repository.revokeAllUserSessions(userId);
    this.repository.logAudit(AuditAction.LOGOUT, ip, userAgent, userId, { global: true }, 'INFO', this.getCorrelationId());
  }
}
