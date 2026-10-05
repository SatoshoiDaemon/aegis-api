import { prisma } from '../../shared/infra/db/prisma';
import { Prisma, type AuditAction, type Severity } from '@prisma/client';
import { logger } from '../../shared/infra/logger/pino';

export class AuthRepository {
  async findUserByEmail(email: string) {
    return prisma.user.findUnique({ where: { email } });
  }

  async findUserById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }

  async createUser(data: Prisma.UserCreateInput) {
    return prisma.user.create({ data });
  }

  async createSession(data: Prisma.SessionUncheckedCreateInput) {
    return prisma.session.create({ data });
  }

  async findSessionByTokenHash(refreshTokenHash: string) {
    return prisma.session.findFirst({
      where: { refreshTokenHash },
      include: { user: true },
    });
  }

  async revokeSession(sessionId: string) {
    return prisma.session.update({
      where: { id: sessionId },
      data: { revokedAt: new Date() },
    });
  }

  async revokeAllUserSessions(userId: string) {
    return prisma.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
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
