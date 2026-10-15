import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { analyzeHar } from '../src/analyze.js';
import { renderReport } from '../src/report.js';

const phases = (total, wait = (total - 25) * .65) => ({ blocked: 0, dns: 5, connect: 15, ssl: 10, send: 5, wait, receive: total - 25 - wait });
const scenarios = [
  [200, 140, '/app', 'text/html'], [200, 85, '/assets/main.js', 'text/javascript'],
  [200, 40, '/assets/style.css', 'text/css'], [200, 160, '/api/profile', 'application/json'],
  [401, 130, '/api/private', 'application/json'], [200, 110, '/api/items', 'application/json'],
  [429, 210, '/api/search', 'application/json'], [503, 2600, '/api/orders', 'application/json'],
  [200, 4200, '/api/export', 'application/json'], [0, 175, '/api/events', 'application/json'],
  [200, 3400, '/download', 'application/octet-stream'], [200, 190, '/api/items', 'application/json'],
  [200, 95, '/assets/logo.png', 'image/png'], [200, 210, '/api/profile', 'application/json'],
  [200, 80, '/api/ping', 'text/plain'], [200, 75, '/api/ping', 'text/plain'],
];
const entries = scenarios.map(([status, time, path, mimeType], index) => ({
  startedDateTime: new Date(Date.UTC(2026, 9, 15, 0, 0, 0, index * 130)).toISOString(),
  time,
  request: { method: 'GET', url: `https://SYNTHETIC_PRIVATE_HOST.test${path}?token=SYNTHETIC_TOKEN`,
    headers: [{ name: 'Authorization', value: 'Bearer SYNTHETIC_TOKEN' }],
    queryString: [{ name: 'token', value: 'SYNTHETIC_TOKEN' }], cookies: [], headersSize: 200, bodySize: 0 },
  response: { status, statusText: 'SYNTHETIC_ONLY', headers: [], cookies: [], headersSize: 110,
    bodySize: index === 10 ? 1024 * 1024 * 3 : 420,
    content: { size: index === 10 ? 1024 * 1024 * 3 : 420, mimeType, text: 'SYNTHETIC_PRIVATE_BODY' } },
  cache: {}, timings: index === 10 ? phases(time, 150) : index === 8 ? phases(time, 4000) : phases(time),
}));
const capture = { log: { version: '1.2', creator: { name: 'Synthetic demo, not a browser recording', version: '1' }, entries } };
await mkdir(resolve('artifacts'), { recursive: true });
const destination = await mkdtemp(resolve('artifacts/demo-'));
const report = analyzeHar(Buffer.from(JSON.stringify(capture)));
await writeFile(join(destination, 'capture.har'), JSON.stringify(capture, null, 2));
await writeFile(join(destination, 'report.json'), JSON.stringify(report, null, 2));
await writeFile(join(destination, 'report.html'), renderReport(report));
console.log(JSON.stringify({ synthetic: true, destination, report: join(destination, 'report.html'), summary: report.summary }, null, 2));
