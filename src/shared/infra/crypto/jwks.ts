import { createPublicKey, createPrivateKey, createHash } from 'node:crypto';

export function publicJwk(privateKey: string, publicKey: string) {
  const key = createPublicKey(publicKey);
  const derived = createPublicKey(createPrivateKey(privateKey)).export({ format: 'der', type: 'spki' });
  if (!derived.equals(key.export({ format: 'der', type: 'spki' }))) throw new Error('JWT key pair does not match');
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error('JWT requires RSA >= 2048 bits');
  const jwk = key.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })).digest('base64url');
  return { ...jwk, kid, use: 'sig', alg: 'RS256' };
}

export function jwtIssuer() {
  const issuer = process.env.JWT_ISSUER || 'http://localhost:3333';
  const url = new URL(issuer);
  if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') throw new Error('JWT_ISSUER must use HTTPS in production');
  return issuer.replace(/\/$/, '');
}
export function jwtAudience() { return process.env.JWT_AUDIENCE || 'aegis-api'; }
