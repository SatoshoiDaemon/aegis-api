// Run only against a disposable local/staging deployment with its own database.
import { performance } from 'node:perf_hooks';
const target = process.env.LOAD_BASE_URL ?? 'http://localhost:3333';
if (process.env.LOAD_ACK !== 'disposable-environment') throw new Error('Set LOAD_ACK=disposable-environment');
const concurrency = Number(process.env.LOAD_CONCURRENCY ?? 4);
const iterations = Number(process.env.LOAD_ITERATIONS ?? 10);
if (![concurrency, iterations].every(n => Number.isInteger(n) && n > 0 && n <= 1000)) throw new Error('Invalid load configuration');
const mode = process.env.LOAD_MODE ?? 'me';
if (!['me', 'refresh', 'login'].includes(mode)) throw new Error('LOAD_MODE must be me, refresh or login');
const timings = [], statuses = {};
const start = performance.now();
let measurementStart;
await Promise.all(Array.from({ length: concurrency }, async (_, worker) => {
  // Separate account + rate-limit identity per worker; provision via admin-controlled staging environment.
  const email = `load-${Date.now()}-${worker}@example.test`;
  const password = 'Load-test-only-password-123!';
  async function call(path, body, token, measured = false) {
    const before = performance.now();
    let response;
    try {
      response = await fetch(target + path, { method: body ? 'POST' : 'GET', headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10000) });
      if (measured) statuses[response.status] = (statuses[response.status] ?? 0) + 1;
      const data = await response.json();
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return data;
    } catch (error) { if (measured && !response) statuses.network_error = (statuses.network_error ?? 0) + 1; throw error; }
    finally { if (measured) timings.push(performance.now() - before); }
  }
  await call('/auth/register', { email, password });
  let tokens = await call('/auth/login', { email, password });
  measurementStart ??= performance.now();
  for (let i = 0; i < iterations; i++) {
    try {
      if (mode === 'me') await call('/auth/me', undefined, tokens.accessToken, true);
      else if (mode === 'refresh') tokens = await call('/auth/refresh', { refreshToken: tokens.refreshToken }, undefined, true);
      else await call('/auth/login', { email, password }, undefined, true);
    } catch { break; }
  }
}));
timings.sort((a, b) => a - b);
const percentile = p => timings[Math.min(timings.length - 1, Math.ceil(timings.length * p) - 1)] ?? null;
console.log(JSON.stringify({ mode, requests: timings.length, statuses, elapsedSeconds: (performance.now() - start) / 1000, p50Ms: percentile(.5), p95Ms: percentile(.95), p99Ms: percentile(.99), measuredRps: timings.length / ((performance.now() - measurementStart) / 1000) }, null, 2));
if (Object.keys(statuses).some(status => status !== '200')) process.exitCode = 1;
