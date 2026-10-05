import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { logger } from '../logger/pino';

const keysDir = path.join(__dirname, '../../../../keys');
const privateKeyPath = path.join(keysDir, 'dev.private.pem');
const publicKeyPath = path.join(keysDir, 'dev.public.pem');

export function getJwtKeys(): { privateKey: string; publicKey: string } {
  // Produção: Inject via ENV
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.PRIVATE_KEY || !process.env.PUBLIC_KEY) {
      throw new Error('Missing PRIVATE_KEY or PUBLIC_KEY in production environment');
    }
    return {
      privateKey: process.env.PRIVATE_KEY.replace(/\\n/g, '\n'),
      publicKey: process.env.PUBLIC_KEY.replace(/\\n/g, '\n'),
    };
  }

  // Dev: Fallback
  if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
    return {
      privateKey: fs.readFileSync(privateKeyPath, 'utf8'),
      publicKey: fs.readFileSync(publicKeyPath, 'utf8'),
    };
  }

  logger.warn('WARN: using ephemeral RSA keys. Generating 2048-bit RS256 keys...');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }

  fs.writeFileSync(privateKeyPath, privateKey);
  fs.writeFileSync(publicKeyPath, publicKey);
  fs.chmodSync(privateKeyPath, 0o600);
  fs.chmodSync(publicKeyPath, 0o644);

  return { privateKey, publicKey };
}
