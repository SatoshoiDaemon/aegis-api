import 'fastify';
declare module 'fastify' { interface FastifyContextConfig { rateLimit?: { max: number; timeWindow: string } } }
