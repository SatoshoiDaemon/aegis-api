import Redis from 'ioredis';

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

export const redis = new Redis(redisUrl, {
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
  connectTimeout: 1000,
  commandTimeout: 1000,
});

redis.on('error', (err) => {
  console.error('[Redis Error]', err);
});
