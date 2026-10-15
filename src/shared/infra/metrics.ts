import { FastifyInstance } from 'fastify';
const buckets = [0.01, 0.05, 0.1, 0.5, 1, 5, Infinity];
export function observeRequests(app: FastifyInstance) {
  const rows = new Map<string, { count: number; sum: number; buckets: number[] }>();
  app.addHook('onResponse', async (request, reply) => {
    // Use route templates, never raw URLs or user identifiers as metric labels.
    const route = request.routeOptions.url || '/unmatched';
    const labels = `method=${JSON.stringify(request.method)},route=${JSON.stringify(route)},status=${JSON.stringify(String(reply.statusCode))}`;
    const row = rows.get(labels) || { count: 0, sum: 0, buckets: buckets.map(() => 0) };
    const seconds = reply.elapsedTime / 1000;
    row.count++; row.sum += seconds;
    buckets.forEach((limit, index) => { if (seconds <= limit) row.buckets[index]++; });
    rows.set(labels, row);
    request.log.info({ route, statusCode: reply.statusCode, durationMs: reply.elapsedTime }, 'request_completed');
  });
  app.get('/metrics', async (request, reply) => {
    if (!process.env.METRICS_TOKEN || request.headers.authorization !== `Bearer ${process.env.METRICS_TOKEN}`) return reply.code(404).send();
    const lines = ['# TYPE aegis_http_requests_total counter', '# TYPE aegis_http_request_duration_seconds histogram'];
    for (const [labels, row] of rows) {
      lines.push(`aegis_http_requests_total{${labels}} ${row.count}`);
      lines.push(`aegis_http_request_duration_seconds_sum{${labels}} ${row.sum}`);
      lines.push(`aegis_http_request_duration_seconds_count{${labels}} ${row.count}`);
      buckets.forEach((limit, i) => lines.push(`aegis_http_request_duration_seconds_bucket{${labels},le="${limit === Infinity ? '+Inf' : limit}"} ${row.buckets[i]}`));
    }
    return reply.type('text/plain; version=0.0.4').send(lines.join('\n') + '\n');
  });
}
