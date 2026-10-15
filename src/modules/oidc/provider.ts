import { FastifyInstance } from 'fastify';
import { createPrivateKey } from 'node:crypto';
import { z } from 'zod';
import { getJwtKeys } from '../../shared/infra/crypto/keys';
import { publicJwk } from '../../shared/infra/crypto/jwks';
import { prisma } from '../../shared/infra/db/prisma';
import { authMiddleware } from '../../shared/http/middlewares/authMiddleware';
import { OidcAdapter } from './adapter';

// Opt-in: standard OAuth/OIDC mechanics are owned by oidc-provider, not hand-written here.
export async function registerOidc(app: FastifyInstance) {
  if (process.env.OIDC_ENABLED !== 'true') return;
  const { default: Provider } = await import('oidc-provider');
  const issuer = z.string().url().parse(process.env.OIDC_ISSUER);
  const ui = z.string().url().parse(process.env.OIDC_UI_URL);
  if (new URL(issuer).pathname !== '/oidc') throw new Error('OIDC_ISSUER must end in /oidc');
  if (process.env.NODE_ENV === 'production' && [issuer, ui].some(url => new URL(url).protocol !== 'https:')) throw new Error('OIDC requires HTTPS in production');
  const clients = z.array(z.object({
    client_id: z.string().min(1), redirect_uris: z.array(z.string().url()).min(1),
    response_types: z.tuple([z.literal('code')]), grant_types: z.tuple([z.literal('authorization_code')]),
    token_endpoint_auth_method: z.literal('none'),
  })).min(1).parse(JSON.parse(process.env.OIDC_CLIENTS || '[]'));
  if (process.env.NODE_ENV === 'production' && clients.some(client => client.redirect_uris.some(uri => new URL(uri).protocol !== 'https:'))) throw new Error('OIDC redirect URIs require HTTPS');
  const cookieKeys = z.array(z.string().min(32)).min(1).parse(JSON.parse(process.env.OIDC_COOKIE_KEYS || '[]'));
  const keys = getJwtKeys();
  const jwk = { ...createPrivateKey(keys.privateKey).export({ format: 'jwk' }), kid: publicJwk(keys.privateKey, keys.publicKey).kid, use: 'sig', alg: 'RS256' };
  const provider = new Provider(issuer, {
    adapter: OidcAdapter, clients, jwks: { keys: [jwk] }, cookies: { keys: cookieKeys },
    features: { devInteractions: { enabled: false }, revocation: { enabled: true }, introspection: { enabled: false } },
    pkce: { required: () => true }, responseTypes: ['code'], scopes: ['openid', 'email'],
    claims: { openid: ['sub'], email: ['email', 'email_verified'] },
    ttl: { AccessToken: 900, AuthorizationCode: 60, IdToken: 900, Interaction: 300, Session: 3600, Grant: 3600 },
    interactions: { url: (_ctx, interaction) => `/oidc/interaction/${interaction.uid}` },
    async findAccount(_ctx, id) {
      const user = await prisma.user.findUnique({ where: { id } });
      if (!user) return undefined;
      return { accountId: id, async claims() { return { sub: id, email: user.email, email_verified: user.isVerified }; } };
    },
  });
  provider.proxy = process.env.OIDC_TRUST_PROXY === 'true';
  provider.on('server_error', (_ctx, error) => app.log.error({ err: error }, 'oidc_server_error'));
  const callback = provider.callback();

  app.get('/oidc/interaction/:uid', async (request, reply) => {
    const details = await provider.interactionDetails(request.raw, reply.raw);
    if (details.uid !== (request.params as { uid: string }).uid) return reply.code(400).send({ error: 'invalid_interaction' });
    if (!request.headers.authorization) {
      const location = new URL(ui); location.searchParams.set('uid', details.uid);
      return reply.redirect(location.href);
    }
    await authMiddleware(request);
    reply.header('cache-control', 'no-store');
    return { uid: details.uid, prompt: details.prompt.name, clientId: details.params.client_id, scope: details.params.scope };
  });
  app.post('/oidc/interaction/:uid', { preValidation: [authMiddleware] }, async (request, reply) => {
    const { consent } = z.object({ consent: z.boolean() }).parse(request.body);
    const details = await provider.interactionDetails(request.raw, reply.raw);
    if (details.uid !== (request.params as { uid: string }).uid) return reply.code(400).send({ error: 'invalid_interaction' });
    const { sub } = request.user as { sub: string };
    // Return JSON with the provider resume URL so fetch clients can navigate the browser.
    if (!consent) {
      const redirectTo = await provider.interactionResult(request.raw, reply.raw, { error: 'access_denied' }, { mergeWithLastSubmission: false });
      return reply.header('cache-control', 'no-store').send({ redirectTo });
    }
    if (details.session?.accountId && details.session.accountId !== sub) return reply.code(409).send({ error: 'account_mismatch' });
    if (details.prompt.name === 'login') {
      const redirectTo = await provider.interactionResult(request.raw, reply.raw, { login: { accountId: sub } }, { mergeWithLastSubmission: false });
      return reply.header('cache-control', 'no-store').send({ redirectTo });
    }
    if (details.prompt.name !== 'consent') return reply.code(400).send({ error: 'unsupported_interaction' });
    const grant = details.grantId ? await provider.Grant.find(details.grantId) : new provider.Grant({ accountId: sub, clientId: String(details.params.client_id) });
    if (!grant) return reply.code(400).send({ error: 'invalid_grant' });
    const scopes = details.prompt.details.missingOIDCScope as string[] | undefined;
    const claims = details.prompt.details.missingOIDCClaims as string[] | undefined;
    if (scopes) grant.addOIDCScope(scopes.join(' '));
    if (claims) grant.addOIDCClaims(claims);
    const redirectTo = await provider.interactionResult(request.raw, reply.raw, { consent: { grantId: await grant.save() } }, { mergeWithLastSubmission: true });
    return reply.header('cache-control', 'no-store').send({ redirectTo });
  });
  // Dispatch before Fastify consumes form bodies: oidc-provider owns protocol parsing.
  app.all('/oidc/*', { onRequest: async (request, reply) => {
    request.raw.url = request.raw.url!.replace(/^\/oidc/, '') || '/';
    for (const [name, value] of Object.entries(reply.getHeaders())) {
      if (value !== undefined) reply.raw.setHeader(name, value);
    }
    reply.hijack();
    await callback(request.raw, reply.raw);
  } }, async () => {});
  app.get('/.well-known/oauth-authorization-server/oidc', async (_request, reply) => reply.redirect('/oidc/.well-known/oauth-authorization-server'));
}
