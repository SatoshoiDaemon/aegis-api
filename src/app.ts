import fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
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

export const app = fastify({ loggerInstance: logger });

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
  
  // Rate Limiting (Global and Specific fallback)
  await app.register(rateLimit, {
    max: 100,
    timeWindow: '1 minute',
    redis,
    nameSpace: 'rl-api-',
  });

  // JWT with RS256 keys
  const keys = getJwtKeys();
  await app.register(jwt, {
    secret: {
      private: keys.privateKey,
      public: keys.publicKey
    },
    sign: { algorithm: 'RS256' },
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
  app.addHook('onRequest', correlationIdMiddleware);

  app.get('/health', async () => ({ status: 'ok', time: new Date() }));

  // Register Modules
  app.register(authRoutes, { prefix: '/auth' });

  // Global Error Handler
  app.setErrorHandler((error, request, reply) => {
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

    if (statusCode === 429) {
      return reply.status(429).send({ error: 'Too Many Requests' });
    }

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
