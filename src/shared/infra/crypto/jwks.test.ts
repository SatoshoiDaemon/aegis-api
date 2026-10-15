import { generateKeyPairSync, createPublicKey, sign, verify } from 'node:crypto';
import { publicJwk } from './jwks';
it('publishes a stable public-only key that verifies signatures', () => {
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  const jwk = publicJwk(keys.privateKey, keys.publicKey);
  expect(jwk).not.toHaveProperty('d'); expect(jwk).not.toHaveProperty('p');
  expect(publicJwk(keys.privateKey, keys.publicKey).kid).toBe(jwk.kid);
  const signature = sign('RSA-SHA256', Buffer.from('payload'), keys.privateKey);
  expect(verify('RSA-SHA256', Buffer.from('payload'), createPublicKey({ key: jwk, format: 'jwk' }), signature)).toBe(true);
});
