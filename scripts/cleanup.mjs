import 'dotenv/config';
import { prisma } from '../dist/shared/infra/db/prisma.js';
const now = new Date();
const auditDays = Number(process.env.AUDIT_RETENTION_DAYS || 90);
if (!Number.isInteger(auditDays) || auditDays < 1) throw new Error('Invalid AUDIT_RETENTION_DAYS');
try {
  // Keep revoked refresh tokens until their original expiry to preserve replay detection.
  const results = await prisma.$transaction([
    prisma.session.deleteMany({ where: { expiresAt: { lt: now } } }),
    prisma.emailToken.deleteMany({ where: { expiresAt: { lt: now } } }),
    prisma.oidcRecord.deleteMany({ where: { expiresAt: { lt: now } } }),
    prisma.auditLog.deleteMany({ where: { createdAt: { lt: new Date(Date.now() - auditDays * 86400000) } } }),
  ]);
  console.log(JSON.stringify({ sessions: results[0].count, emailTokens: results[1].count, oidc: results[2].count, auditLogs: results[3].count }));
} finally { await prisma.$disconnect(); }
