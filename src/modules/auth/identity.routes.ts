import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { IdentityService } from './identity.service';
import { authMiddleware } from '../../shared/http/middlewares/authMiddleware';
import { forgotPasswordSchema, resetPasswordSchema } from './auth.schemas';
import { prisma } from '../../shared/infra/db/prisma';
import { DomainErrors } from '../../shared/errors/AppError';

export async function identityRoutes(app: FastifyInstance) {
  const service = new IdentityService();
  const rateLimit = { max: 3, timeWindow: '5 minutes' };
  const accepted = { message: 'If eligible, an email will be sent.' };
  app.post('/forgot-password', { config: { rateLimit } }, async (request, reply) => {
    const { email } = forgotPasswordSchema.parse(request.body);
    if (!process.env.MAIL_WEBHOOK_URL || !process.env.MAIL_WEBHOOK_TOKEN) throw DomainErrors.ServiceUnavailable;
    await service.request(email, 'RESET_PASSWORD');
    return reply.code(202).send(accepted);
  });
  app.post('/reset-password', { config: { rateLimit } }, async (request, reply) => {
    const { token, newPassword } = resetPasswordSchema.extend({ token: z.string().regex(/^[a-f0-9]{64}$/) }).parse(request.body);
    await service.consume(token, 'RESET_PASSWORD', newPassword);
    return reply.code(204).send();
  });
  app.post('/verification-email', { preValidation: [authMiddleware], config: { rateLimit } }, async (request, reply) => {
    if (!process.env.MAIL_WEBHOOK_URL || !process.env.MAIL_WEBHOOK_TOKEN) throw DomainErrors.ServiceUnavailable;
    const { sub } = request.user as { sub: string };
    const user = await prisma.user.findUniqueOrThrow({ where: { id: sub } });
    await service.request(user.email, 'VERIFY_EMAIL');
    return reply.code(202).send(accepted);
  });
  app.post('/verify-email', { config: { rateLimit: { max: 10, timeWindow: '5 minutes' } } }, async (request, reply) => {
    const { token } = z.object({ token: z.string().regex(/^[a-f0-9]{64}$/) }).parse(request.body);
    await service.consume(token, 'VERIFY_EMAIL');
    return reply.code(204).send();
  });
}
