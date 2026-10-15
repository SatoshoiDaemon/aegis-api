import { createHash, randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import { TokenType } from '@prisma/client';
import { prisma } from '../../shared/infra/db/prisma';
import { DomainErrors } from '../../shared/errors/AppError';
import { logger } from '../../shared/infra/logger/pino';

const hash = (value: string) => createHash('sha256').update(value).digest('hex');
export interface IdentityMessage { to: string; type: TokenType; token: string; expiresAt: string }
export async function deliverIdentityMessage(message: IdentityMessage) {
  const endpoint = process.env.MAIL_WEBHOOK_URL;
  const secret = process.env.MAIL_WEBHOOK_TOKEN;
  if (!endpoint || !secret) throw DomainErrors.ServiceUnavailable;
  if (process.env.NODE_ENV === 'production' && new URL(endpoint).protocol !== 'https:') throw new Error('Mail webhook must use HTTPS');
  const response = await fetch(endpoint, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
    headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}` }, body: JSON.stringify(message),
  });
  if (!response.ok) throw new Error('Mail delivery rejected');
}

export class IdentityService {
  constructor(private readonly deliver = deliverIdentityMessage) {}

  async request(email: string, type: TokenType) {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || (type === 'VERIFY_EMAIL' && user.isVerified)) return;
    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + (type === 'RESET_PASSWORD' ? 30 : 1440) * 60000);
    const stored = await prisma.$transaction(async tx => {
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${user.id}::uuid FOR UPDATE`;
      const recent = await tx.emailToken.findFirst({ where: { userId: user.id, type, createdAt: { gt: new Date(Date.now() - 60000) } } });
      if (recent) return null;
      await tx.emailToken.deleteMany({ where: { userId: user.id, type } });
      return tx.emailToken.create({ data: { userId: user.id, type, tokenHash: hash(token), expiresAt } });
    });
    if (!stored) return;
    try { await this.deliver({ to: user.email, type, token, expiresAt: expiresAt.toISOString() }); }
    catch {
      await prisma.emailToken.deleteMany({ where: { id: stored.id } });
      // Keep the public response identical for unknown users and delivery failures.
      logger.error({ event: 'identity_delivery_failed', type }, 'Identity message delivery failed');
    }
  }

  async consume(token: string, type: TokenType, newPassword?: string) {
    const tokenHash = hash(token);
    const original = await prisma.emailToken.findFirst({ where: { tokenHash, type } });
    if (!original) throw DomainErrors.InvalidToken;
    const passwordHash = newPassword ? await argon2.hash(newPassword) : undefined;
    const consumed = await prisma.$transaction(async tx => {
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${original.userId}::uuid FOR UPDATE`;
      const deleted = await tx.emailToken.deleteMany({ where: { id: original.id, tokenHash, type, expiresAt: { gt: new Date() } } });
      if (deleted.count !== 1) return false;
      if (type === 'RESET_PASSWORD') {
        if (!passwordHash) throw new Error('Password required');
        await tx.user.update({ where: { id: original.userId }, data: { passwordHash } });
        await tx.session.updateMany({ where: { userId: original.userId, revokedAt: null }, data: { revokedAt: new Date() } });
        await tx.oidcRecord.deleteMany({ where: { accountId: original.userId } });
        await tx.emailToken.deleteMany({ where: { userId: original.userId, type } });
        await tx.auditLog.create({ data: { userId: original.userId, action: 'PASSWORD_RESET' } });
      } else await tx.user.update({ where: { id: original.userId }, data: { isVerified: true } });
      return true;
    });
    if (!consumed) throw DomainErrors.InvalidToken;
  }
}
