# OAuth2 / OpenID Connect

The provider is opt-in and uses `oidc-provider` for protocol validation, PKCE, authorization
codes, cookies, ID tokens and revocation. Its durable adapter stores state in `oidc_records`.
It does not share REST refresh tokens or REST JWT audiences.

## Configuration

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=https://auth.example.com/oidc
OIDC_UI_URL=https://login.example.com/identity
OIDC_COOKIE_KEYS=["replace-with-a-random-secret-of-at-least-32-characters"]
OIDC_CLIENTS=[{"client_id":"my-web-app","redirect_uris":["https://app.example.com/callback"],"response_types":["code"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}]
```

Issuer must use the `/oidc` path, with no trailing slash. HTTPS is required for issuer,
UI and redirect URIs in production. Register public clients explicitly; every client must
use Authorization Code with PKCE S256. No dynamic client registration, implicit grant,
password grant or client credentials grant is enabled. OAuth refresh tokens are not enabled.
Cookie keys are shared across instances; preserve old keys during cookie-key rollover.
Private/public RSA keys use the same configuration as REST JWTs.

Only set `OIDC_TRUST_PROXY=true` behind a trusted reverse proxy that overwrites forwarded
headers and blocks direct access. Configure `CORS_ORIGINS` to include the login frontend
for its REST/interaction calls. Do not expose arbitrary clients through a wildcard origin.

## Discovery and protocol endpoints

Start with `GET /oidc/.well-known/openid-configuration`; use its endpoint URLs rather than
hardcoding provider paths. The OAuth metadata location is also available at
`/.well-known/oauth-authorization-server/oidc`. Use the OIDC `jwks_uri` for ID tokens,
and `/.well-known/jwks.json` for REST access JWTs. Those token types are not interchangeable.

## Login and consent UI contract

A custom frontend is required. There is no development auto-consent page in production.

1. The client navigates to the discovered authorization endpoint with `client_id`, exact
   `redirect_uri`, `response_type=code`, `scope=openid email`, `state`, `nonce`, PKCE
   `code_challenge` and `code_challenge_method=S256`.
2. The provider redirects to `/oidc/interaction/:uid`. Unauthenticated navigation is
   redirected to `OIDC_UI_URL?uid=...`.
3. The UI authenticates using `/auth/login` and keeps the REST access JWT in memory.
   Fetch `GET /oidc/interaction/:uid` with that JWT and `credentials: include`. The
   provider's signed interaction cookie must be included. Display `clientId`, `scope`
   and `prompt` from this response; never trust client labels supplied in the URL.
4. After explicit user action, POST JSON `{ "consent": true }` to the same interaction
   endpoint with bearer JWT and credentials. Denial uses `{ "consent": false }`.
   Navigate the browser to the returned `redirectTo`. Login and consent can require
   separate interaction rounds; repeat the UI flow when redirected back.
5. The provider redirects the user to the registered callback with `code` and `state`.
   The client validates `state` and exchanges the code with its original `code_verifier`,
   `client_id` and exact `redirect_uri` using a form-encoded request to `token_endpoint`.
   Validate the ID token signature, issuer, audience, expiry and original nonce.

Deploy the UI and API under the same site for browser cookie compatibility. The bearer
JWT plus provider-signed interaction cookie binds submissions to the authenticated user;
account changes during an existing interaction are rejected. The UI must explicitly show
and request consent. It must not auto-submit consent on page load.

## Session boundaries

OIDC browser sessions/grants are separate from REST sessions. `/auth/logout` revokes a
REST session; it is not OIDC single logout. Use the provider's discovered end-session and
revocation endpoints for OIDC sessions/tokens. Resetting a password removes persisted
OIDC state for that account and revokes REST sessions. Already-issued ID tokens remain
cryptographically valid until expiry and must not be used as API access tokens.

`pnpm test:oidc` exercises discovery, login/consent, PKCE exchange, signature/nonce,
userinfo, code replay, invalid PKCE and atomic adapter consumption. Before enabling a
public identity service, validate your deployed UI, proxy/cookie settings and relying
parties with the OpenID conformance suite. The library's certification does not certify
this application's custom adapter or deployment.

References: [oidc-provider integration and adapter contract](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md),
[OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700),
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
