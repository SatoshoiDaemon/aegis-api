import { identityRoutes } from './identity.routes';
import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AuthRepository } from './auth.repository';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { authMiddleware } from '../../shared/http/middlewares/authMiddleware';
import { registerSchema, loginSchema, refreshSchema } from './auth.schemas';

export async function authRoutes(app: FastifyInstance) {
  const repository = new AuthRepository();
  const service = new AuthService(repository);
  const controller = new AuthController(service);

  app.addHook('onSend', async (_request, reply) => { reply.header('cache-control', 'no-store'); });
  await app.register(identityRoutes);
  app.get('/me', { preValidation: [authMiddleware] }, async (request, reply) => {
    const claims = request.user as { sub: string };
    const user = await repository.findUserById(claims.sub);
    if (!user) return reply.code(401).send({ error: 'invalid_token' });
    return { id: user.id, email: user.email, role: user.role, isVerified: user.isVerified, createdAt: user.createdAt };
  });
  app.post('/register', {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
    handler: async (request, reply) => {
      const data = registerSchema.parse(request.body);
      request.body = data;
      return controller.register(request as any, reply);
    }
  });

  app.post('/login', {
    config: { rateLimit: { max: 5, timeWindow: '5 minutes' } }, // Harder
    handler: async (request, reply) => {
      const data = loginSchema.parse(request.body);
      request.body = data;
      return controller.login(request as any, reply);
    }
  });

  app.post('/refresh', {
    config: { rateLimit: { max: 20, timeWindow: '5 minutes' } }, // More tolerant
    handler: async (request, reply) => {
      const data = refreshSchema.parse(request.body);
      request.body = data;
      return controller.refresh(request as any, reply);
    }
  });

  app.post('/logout', {
    preValidation: [authMiddleware],
    handler: async (request, reply) => {
      return controller.logout(request, reply);
    }
  });

  // Session Granularity Endpoints
  app.get('/sessions', {
    preValidation: [authMiddleware],
    handler: async (request, reply) => controller.getSessions(request, reply)
  });

  app.delete('/sessions/:id', {
    preValidation: [authMiddleware],
    handler: async (request, reply) => {
      z.object({ id: z.string().uuid() }).parse(request.params);
      return controller.revokeSession(request as any, reply);
    }
  });

  app.delete('/sessions', {
    preValidation: [authMiddleware],
    handler: async (request, reply) => controller.revokeAllSessions(request, reply)
  });
}
