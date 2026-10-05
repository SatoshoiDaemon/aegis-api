import pino from 'pino';
import { requestContext } from '@fastify/request-context';

export const logger = pino({
  level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
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
