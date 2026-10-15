import { Prisma, OidcRecord } from '@prisma/client';
import { prisma } from '../../shared/infra/db/prisma';

export class OidcAdapter {
  constructor(private readonly model: string) {}
  async upsert(id: string, payload: Record<string, any>, expiresIn: number) {
    const data = { payload: payload as Prisma.InputJsonValue, uid: payload.uid as string | undefined,
      grantId: payload.grantId as string | undefined, accountId: payload.accountId as string | undefined,
      expiresAt: expiresIn ? new Date(Date.now() + expiresIn * 1000) : null };
    await prisma.oidcRecord.upsert({ where: { model_id: { model: this.model, id } }, create: { model: this.model, id, ...data }, update: data });
  }
  private unpack(record: OidcRecord | null) {
    if (!record || (record.expiresAt && record.expiresAt <= new Date())) return undefined;
    return { ...record.payload as Record<string, any>, ...(record.consumedAt ? { consumed: record.consumedAt } : {}) };
  }
  async find(id: string) { return this.unpack(await prisma.oidcRecord.findUnique({ where: { model_id: { model: this.model, id } } })); }
  async findByUid(uid: string) { return this.unpack(await prisma.oidcRecord.findFirst({ where: { model: this.model, uid } })); }
  async findByUserCode(userCode: string) { return this.unpack(await prisma.oidcRecord.findFirst({ where: { model: this.model, payload: { path: ['userCode'], equals: userCode } } })); }
  async consume(id: string) {
    const result = await prisma.oidcRecord.updateMany({ where: { model: this.model, id, consumedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }, data: { consumedAt: Math.floor(Date.now() / 1000) } });
    if (result.count !== 1) {
      const { errors } = await import('oidc-provider');
      throw new errors.InvalidGrant('OIDC artifact already consumed or expired');
    }
  }
  async destroy(id: string) { await prisma.oidcRecord.deleteMany({ where: { model: this.model, id } }); }
  async revokeByGrantId(grantId: string) { await prisma.oidcRecord.deleteMany({ where: { grantId } }); }
}
