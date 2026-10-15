export interface User { id: string; email: string; role: 'USER' | 'ADMIN'; isVerified: boolean; createdAt: string }
export interface Tokens { accessToken: string; refreshToken: string }
export interface Session { id: string; userAgent: string | null; ip: string | null; expiresAt: string; createdAt: string; revokedAt: string | null }
export class AegisError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string, public readonly correlationId: string | null, public readonly retryAfter: string | null) { super(message); this.name = 'AegisError'; }
}
export class AegisClient {
  private tokens?: Tokens;
  private refreshing?: Promise<Tokens>;
  private generation = 0;
  constructor(private readonly options: { baseUrl: string; fetch?: typeof fetch; timeoutMs?: number; onTokens?: (tokens: Tokens | undefined) => void }) {}
  setTokens(tokens?: Tokens) { this.generation++; this.tokens = tokens; this.options.onTokens?.(tokens); }
  private async request<T>(method: string, path: string, body?: unknown, authenticated = false): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (authenticated) {
      if (!this.tokens) throw new AegisError(401, 'missing_tokens', 'Login required', null, null);
      headers.authorization = `Bearer ${this.tokens.accessToken}`;
    }
    const response = await (this.options.fetch ?? fetch)(this.options.baseUrl.replace(/\/$/, '') + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(this.options.timeoutMs ?? 10000), redirect: 'error',
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({})) as { error?: string; message?: string };
      throw new AegisError(response.status, error.error ?? 'http_error', error.message ?? response.statusText, response.headers.get('x-correlation-id'), response.headers.get('retry-after'));
    }
    return response.status === 204 ? undefined as T : response.json() as Promise<T>;
  }
  register(email: string, password: string) { return this.request<Pick<User, 'id' | 'email'>>('POST', '/auth/register', { email, password }); }
  async login(email: string, password: string) {
    const result = await this.request<Tokens & { user: Pick<User, 'id' | 'email' | 'role'> }>('POST', '/auth/login', { email, password });
    this.setTokens({ accessToken: result.accessToken, refreshToken: result.refreshToken }); return result;
  }
  // One in-flight rotation per instance. No automatic retries of one-time refresh tokens.
  refresh(): Promise<Tokens> {
    if (this.refreshing) return this.refreshing;
    if (!this.tokens) return Promise.reject(new AegisError(401, 'missing_tokens', 'Login required', null, null));
    const generation = this.generation;
    const refreshToken = this.tokens.refreshToken;
    this.refreshing = this.request<Tokens>('POST', '/auth/refresh', { refreshToken }).then(tokens => {
      if (generation === this.generation) this.setTokens(tokens);
      return tokens;
    }).catch(error => {
      if (generation === this.generation && error instanceof AegisError && error.status === 401) this.setTokens(undefined);
      throw error;
    }).finally(() => { this.refreshing = undefined; });
    return this.refreshing;
  }
  me() { return this.request<User>('GET', '/auth/me', undefined, true); }
  sessions() { return this.request<{ sessions: Session[] }>('GET', '/auth/sessions', undefined, true); }
  revokeSession(id: string) { return this.request<void>('DELETE', `/auth/sessions/${encodeURIComponent(id)}`, undefined, true); }
  async revokeAllSessions() { await this.request<void>('DELETE', '/auth/sessions', undefined, true); this.setTokens(undefined); }
  async logout() { await this.request<{ message: string }>('POST', '/auth/logout', undefined, true); this.setTokens(undefined); }
  forgotPassword(email: string) { return this.request<{ message: string }>('POST', '/auth/forgot-password', { email }); }
  resetPassword(token: string, newPassword: string) { return this.request<void>('POST', '/auth/reset-password', { token, newPassword }); }
  requestVerification() { return this.request<{ message: string }>('POST', '/auth/verification-email', undefined, true); }
  verifyEmail(token: string) { return this.request<void>('POST', '/auth/verify-email', { token }); }
}
