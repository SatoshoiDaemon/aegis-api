import { AuthRepository } from './auth.repository';
import { RegisterInput, LoginInput } from './auth.schemas';
import * as argon2 from 'argon2';
import crypto from 'crypto';
import { logger } from '../../shared/infra/logger/pino';
import { DomainErrors } from '../../shared/errors/AppError';
import { AuditAction } from '@prisma/client';
import { requestContext } from '@fastify/request-context';
import { redis } from '../../shared/infra/redis/redis';
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

  // Redis Cache Revocation (15 min window match exp of Access Token)
  private async blacklistSessionLocal(sessionId: string) {
    await redis.set(`revoked:${sessionId}`, 1, 'EX', 15 * 60).catch(err => {
      logger.warn({ err, sessionId }, 'Failed to set redis blacklist key');
    });
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
    });

    this.repository.logAudit(AuditAction.LOGIN_SUCCESS, ip, userAgent, user.id, { sessionId: session.id }, 'INFO', this.getCorrelationId());

    return { user, session, refreshTokenPlain };
  }

  async refresh(refreshTokenPlain: string, ip?: string, userAgent?: string) {
    const refreshTokenHash = this.hashToken(refreshTokenPlain);
    const session = await this.repository.findSessionByTokenHash(refreshTokenHash);

    if (!session) {
      throw DomainErrors.InvalidToken;
    }

    if (session.revokedAt) {
      logger.warn(`Reuse suspected for session ${session.id} of user ${session.userId}. Revoking all sessions.`);
      const activeSessions = await this.repository.findActiveSessionsByUserId(session.userId);
      await this.repository.revokeAllUserSessions(session.userId);
      await Promise.all(activeSessions.map(({ id }) => this.blacklistSessionLocal(id)));
      
      // Blacklist ALL specific sessions quickly if needed, but the primary hit is already done via revoking global check
      
      this.repository.logAudit(AuditAction.TOKEN_REUSE_DETECTED, ip, userAgent, session.userId, {
        sessionId: session.id,
        originalIp: session.ip
      }, 'CRITICAL', this.getCorrelationId());
      throw DomainErrors.SessionReuseDetected;
    }

    if (session.expiresAt.getTime() < Date.now()) {
      throw DomainErrors.TokenExpired;
    }

    await this.repository.revokeSession(session.id);
    await this.blacklistSessionLocal(session.id); // Add to fast cache

    const newRefreshTokenPlain = this.generateRefreshToken();
    const newRefreshTokenHash = this.hashToken(newRefreshTokenPlain);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);

    const newSession = await this.repository.createSession({
      userId: session.userId,
      refreshTokenHash: newRefreshTokenHash,
      ip,
      userAgent,
      expiresAt,
    });

    this.repository.logAudit(AuditAction.TOKEN_REFRESH, ip, userAgent, session.userId, { newSessionId: newSession.id, oldSessionId: session.id }, 'INFO', this.getCorrelationId());

    return { user: session.user, session: newSession, refreshTokenPlain: newRefreshTokenPlain };
  }

  async logout(sessionId: string, userId: string, ip?: string, userAgent?: string) {
    await this.repository.revokeSession(sessionId);
    await this.blacklistSessionLocal(sessionId);
    this.repository.logAudit(AuditAction.LOGOUT, ip, userAgent, userId, { sessionId }, 'INFO', this.getCorrelationId());
  }

  // Session Management
  async listUserSessions(userId: string) {
    return prisma.session.findMany({
      where: { userId, revokedAt: null },
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
    await this.blacklistSessionLocal(sessionId);
    this.repository.logAudit(AuditAction.LOGOUT, ip, userAgent, userId, { sessionId, explicitRevoke: true }, 'INFO', this.getCorrelationId());
  }

  async revokeAllSessions(userId: string, ip?: string, userAgent?: string) {
    const sessions = await this.repository.findActiveSessionsByUserId(userId);
    await this.repository.revokeAllUserSessions(userId);
    await Promise.all(sessions.map(({ id }) => this.blacklistSessionLocal(id)));
    this.repository.logAudit(AuditAction.LOGOUT, ip, userAgent, userId, { global: true }, 'INFO', this.getCorrelationId());
  }
}
