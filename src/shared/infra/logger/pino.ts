import pino from 'pino';
import { requestContext } from '@fastify/request-context';

export const logger = pino({
  redact: ['req.headers.authorization', 'req.headers.cookie', 'res.headers.set-cookie', 'password', 'token', 'refreshToken', 'accessToken'],
  serializers: { req: req => ({ method: req.method, url: req.url?.split('?')[0], id: req.id }) },
  level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'test' ? 'silent' : process.env.NODE_ENV === 'development' ? 'debug' : 'info'),
  transport:
    process.env.NODE_ENV === 'development'
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname',
          },
        }
      : undefined,
  mixin() {
    return { correlationId: requestContext.get('correlationId') };
  },
});
