import 'dotenv/config';
import { buildApp } from './app';

const PORT = Number(process.env.PORT) || 3333;

async function start() {
  const app = await buildApp();

  try {
    const address = await app.listen({ port: PORT, host: '0.0.0.0' });
    app.log.info(`Server listening at ${address}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }

  const gracefulShutdown = async () => {
    app.log.info('Shutting down server gracefully...');
    await app.close();
    process.exit(0);
  };

  process.on('SIGINT', gracefulShutdown);
  process.on('SIGTERM', gracefulShutdown);
}

start();
