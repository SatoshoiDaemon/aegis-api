import { DomainErrors } from '../../shared/errors/AppError';
import { prisma } from '../../shared/infra/db/prisma';
import { Prisma, type AuditAction, type Severity } from '@prisma/client';
import { logger } from '../../shared/infra/logger/pino';

export class AuthRepository {
  // Every session writer takes the same user-row lock, including login and logout.
  async rotateSession(hash: string, nextHash: string, ip?: string, userAgent?: string) {
    return prisma.$transaction(async tx => {
      const original = await tx.session.findFirst({ where: { refreshTokenHash: hash } });
      if (!original) return { kind: 'invalid' } as const;
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${original.userId}::uuid FOR UPDATE`;
      const session = await tx.session.findUniqueOrThrow({ where: { id: original.id }, include: { user: true } });
      if (session.revokedAt) {
        await tx.session.updateMany({ where: { userId: session.userId, revokedAt: null }, data: { revokedAt: new Date() } });
        return { kind: 'reuse', session } as const;
      }
      if (session.expiresAt <= new Date()) return { kind: 'expired' } as const;
      await tx.session.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
      const next = await tx.session.create({ data: {
        userId: session.userId, refreshTokenHash: nextHash, ip, userAgent,
        expiresAt: session.expiresAt, // Absolute lifetime: rotation cannot extend a stolen session forever.
      } });
      return { kind: 'rotated', session: next, user: session.user, oldSessionId: session.id } as const;
    });
  }

  async findUserByEmail(email: string) {
    return prisma.user.findUnique({ where: { email } });
  }

  async findUserById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }

  async createUser(data: Prisma.UserCreateInput) {
    return prisma.user.create({ data });
  }

  async createSession(data: Prisma.SessionUncheckedCreateInput, expectedPasswordHash: string) {
    return prisma.$transaction(async tx => {
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${data.userId}::uuid FOR UPDATE`;
      const user = await tx.user.findUniqueOrThrow({ where: { id: data.userId } });
      if (user.passwordHash !== expectedPasswordHash) throw DomainErrors.InvalidCredentials;
      return tx.session.create({ data });
    });
  }

  async findSessionByTokenHash(refreshTokenHash: string) {
    return prisma.session.findFirst({
      where: { refreshTokenHash },
      include: { user: true },
    });
  }

  async revokeSession(sessionId: string) {
    return prisma.$transaction(async tx => {
      const session = await tx.session.findUniqueOrThrow({ where: { id: sessionId } });
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${session.userId}::uuid FOR UPDATE`;
      return tx.session.update({ where: { id: sessionId }, data: { revokedAt: new Date() } });
    });
  }

  async revokeAllUserSessions(userId: string) {
    return prisma.$transaction(async tx => {
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${userId}::uuid FOR UPDATE`;
      return tx.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
    });
  }

  async findActiveSessionsByUserId(userId: string) {
    return prisma.session.findMany({
      where: { userId, revokedAt: null },
      select: { id: true },
    });
  }

  logAudit(
    action: AuditAction,
    ip?: string | null, 
    userAgent?: string | null, 
    userId?: string | null, 
    metadata?: any,
    severity: Severity = 'INFO',
    correlationId?: string | null
  ) {
    prisma.auditLog.create({
      data: {
        action,
        severity,
        ip,
        userAgent,
        correlationId,
        userId,
        metadata: metadata || Prisma.JsonNull,
      }
    }).catch((err: unknown) => {
      logger.error({ err, action, userId, correlationId }, '[Audit Error] Failed to write to database');
    });
  }
}
