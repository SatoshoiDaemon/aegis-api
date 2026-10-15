import { AegisClient, AegisError } from '../../../packages/sdk/src';
it('coalesces concurrent refreshes and updates tokens', async () => {
  const fetcher = jest.fn().mockResolvedValue(new Response(JSON.stringify({ accessToken: 'new', refreshToken: 'next' })));
  const client = new AegisClient({ baseUrl: 'https://example.test', fetch: fetcher });
  client.setTokens({ accessToken: 'old', refreshToken: 'original' });
  const results = await Promise.all(Array.from({ length: 20 }, () => client.refresh()));
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(results.every(value => value.accessToken === 'new')).toBe(true);
});
it('exposes structured errors without retrying one-time tokens', async () => {
  const fetcher = jest.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'service_unavailable' }), { status: 503, headers: { 'x-correlation-id': 'trace' } }));
  const client = new AegisClient({ baseUrl: 'https://example.test', fetch: fetcher });
  client.setTokens({ accessToken: 'old', refreshToken: 'original' });
  await expect(client.refresh()).rejects.toMatchObject({ status: 503, correlationId: 'trace', code: 'service_unavailable' });
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(AegisError.prototype).toBeInstanceOf(Error);
});
