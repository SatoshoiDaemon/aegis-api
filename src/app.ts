import { describeAuthRoutes } from './modules/auth/openapi';
import { registerOidc } from './modules/oidc/provider';
import { publicJwk, jwtIssuer, jwtAudience } from './shared/infra/crypto/jwks';
import { rateLimiter } from './shared/http/middlewares/rateLimiter';
import { observeRequests } from './shared/infra/metrics';
import { prisma } from './shared/infra/db/prisma';
import fastify, { FastifyBaseLogger } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import jwt from '@fastify/jwt';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { fastifyRequestContext } from '@fastify/request-context';
import { ZodError } from 'zod';

import { logger } from './shared/infra/logger/pino';
import { redis } from './shared/infra/redis/redis';
import { correlationIdMiddleware } from './shared/http/middlewares/correlationId';
import { getJwtKeys } from './shared/infra/crypto/keys';
import { authRoutes } from './modules/auth/auth.routes';
import { AppError } from './shared/errors/AppError';

export const app = fastify({ loggerInstance: logger as FastifyBaseLogger });

async function setupPlugins() {
  await app.register(fastifyRequestContext);
  
  // Security
  await app.register(helmet, { global: true });
  const configuredOrigins = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  await app.register(cors, {
    origin: process.env.NODE_ENV === 'production' ? configuredOrigins : true,
    credentials: true,
  });
  
  app.addHook('onRequest', correlationIdMiddleware);
  app.addHook('onRequest', rateLimiter);
  observeRequests(app);

  // JWT with RS256 keys
  const keys = getJwtKeys();
  const jwk = publicJwk(keys.privateKey, keys.publicKey);
  app.get('/.well-known/jwks.json', async (_request, reply) => reply.header('cache-control', 'public, max-age=300').send({ keys: [jwk] }));
  await app.register(jwt, {
    secret: {
      private: keys.privateKey,
      public: keys.publicKey
    },
    sign: { algorithm: 'RS256', kid: jwk.kid, iss: jwtIssuer(), aud: jwtAudience() },
    verify: { algorithms: ['RS256'], allowedIss: jwtIssuer(), allowedAud: jwtAudience() },
  });

  // Swagger docs
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'Auth API Service',
        description: 'Microservice for Registration, Login and Session Management',
        version: '1.0.0',
      },
      components: {
        securitySchemes: {
          bearerAuth: {
             type: 'http',
             scheme: 'bearer',
             bearerFormat: 'JWT'
          }
        }
      }
    }
  });

  await app.register(swaggerUi, {
    routePrefix: '/docs',
  });
}

async function setupRoutes() {
  app.get('/health', async () => ({ status: 'ok', time: new Date() }));
  app.get('/ready', async (_request, reply) => {
    const checks = await Promise.allSettled([prisma.$queryRaw`SELECT 1`, redis.ping()]);
    const ready = checks.every(check => check.status === 'fulfilled');
    return reply.code(ready ? 200 : 503).send({ status: ready ? 'ready' : 'unavailable', database: checks[0].status, redis: checks[1].status });
  });

  await registerOidc(app);

  describeAuthRoutes(app);

  // Register Modules
  app.register(authRoutes, { prefix: '/auth' });

  // Global Error Handler
  app.setErrorHandler((error, request, reply) => {
    request.log.warn({ errorType: (error as Error).name, statusCode: (error as AppError).statusCode || 500 }, 'request_failed');
    if (error instanceof ZodError) {
      return reply.status(400).send({
        error: 'Validation Error',
        details: error.flatten().fieldErrors,
      });
    }

    if (error instanceof AppError) {
      return reply.status(error.statusCode).send({
        error: error.errorLabel,
        message: error.message,
        statusCode: error.statusCode
      });
    }

    const fastifyError = error as { statusCode?: number };
    const statusCode = typeof fastifyError.statusCode === 'number' ? fastifyError.statusCode : 500;

    if (['P1001', 'P1002', 'P1017', 'P2024', 'P2028', 'ECONNREFUSED', 'ECONNRESET'].includes((error as { code?: string }).code || '')) return reply.code(503).send({ error: 'service_unavailable', statusCode: 503 });
    if (statusCode >= 400 && statusCode < 500 && statusCode !== 429) return reply.code(statusCode).send({ error: 'bad_request', statusCode });
    if (statusCode === 429) {
      return reply.status(429).send({ error: 'Too Many Requests' });
    }

    if ((error as { code?: string }).code === 'P2002') return reply.code(409).send({ error: 'user_already_exists' });
    logger.error(error);
    reply.status(statusCode).send({
      error: 'internal_server_error',
      message: 'Internal Server Error',
    });
  });
}

export async function buildApp() {
  await setupPlugins();
  await setupRoutes();
  return app;
}
