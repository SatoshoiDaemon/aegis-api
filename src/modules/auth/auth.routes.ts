import { FastifyInstance } from 'fastify';
import { AuthRepository } from './auth.repository';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { authMiddleware } from '../../shared/http/middlewares/authMiddleware';
import { registerSchema, loginSchema, refreshSchema } from './auth.schemas';

export async function authRoutes(app: FastifyInstance) {
  const repository = new AuthRepository();
  const service = new AuthService(repository);
  const controller = new AuthController(service);

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
    handler: async (request, reply) => controller.revokeSession(request as any, reply)
  });

  app.delete('/sessions', {
    preValidation: [authMiddleware],
    handler: async (request, reply) => controller.revokeAllSessions(request, reply)
  });
}
