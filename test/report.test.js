import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import { renderReport } from '../src/report.js';
import { analyzeHar } from '../src/analyze.js';

function fixture() {
  return {
    schemaVersion: 1, reportId: 'har-0123456789abcdef01234567', settings: { slowMs: 2000 },
    summary: { totalEntries: 2, analyzedEntries: 2, filteredEntries: 0, endpoints: 1, requests4xx: 0, requests5xx: 1, networkUnavailable: 0, slowRequests: 1, durationMs: 3200 },
    endpoints: [{ id: 'endpoint-001', method: 'GET', requestCount: 2, errorCount: 1, slowCount: 1, totalMs: 3300, maxMs: 3000 }],
    entries: [
      { sourceEntryIndex: 0, endpointId: 'endpoint-001', method: 'GET', status: 200, startOffsetMs: 0, totalMs: 300, timings: { blocked: 0, dns: 10, connect: 50, ssl: 30, send: 5, wait: 200, receive: 35 }, sizes: { requestBodyBytes: 0, responseBodyBytes: 100, responseContentBytes: 200, requestHeadersBytes: 20, responseHeadersBytes: 30 }, mimeClass: 'json', findings: [] },
      { sourceEntryIndex: 4, endpointId: 'endpoint-001', method: 'GET', status: 503, startOffsetMs: 200, totalMs: 3000, timings: { blocked: -1, dns: -1, connect: -1, ssl: -1, send: 5, wait: 2900, receive: 95 }, sizes: { requestBodyBytes: -1, responseBodyBytes: -1, responseContentBytes: -1, requestHeadersBytes: -1, responseHeadersBytes: -1 }, mimeClass: 'json', findings: ['http-server-error', 'slow', 'wait-dominant'] },
    ],
  };
}
function embedded(html) { return JSON.parse(html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1]); }
function bootstrap(html) { return html.match(/<script>([\s\S]*?)<\/script>/)[1]; }

test('renders a standalone responsive report with request filters and source locators', () => {
  const html = renderReport(fixture());
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /har-0123456789abcdef01234567/);
  for (const expected of ['id="status-filter"', 'id="endpoint-filter"', 'id="request-rows"', 'id="detail"', '@media(max-width:760px)', 'log.entries[42]', 'No recording, request editing, network replay']) assert.ok(html.includes(expected), expected);
  assert.equal(embedded(html).entries[1].sourceEntryIndex, 4);
  assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+href=|fetch\(|XMLHttpRequest|WebSocket\(/i);
});

test('never serializes unknown source fields at any depth', () => {
  const report = fixture();
  const secret = 'sensitive-canary-URL-body-</script><img src=x>';
  report.url = secret; report.summary.raw = secret; report.settings.hostname = secret;
  report.endpoints[0].path = secret;
  report.entries[0].request = { url: secret, headers: [secret], body: secret };
  report.entries[0].timings.raw = secret;
  report.entries[0].sizes.raw = secret;
  const html = renderReport(report);
  assert.ok(!html.includes('sensitive-canary'));
  assert.equal(embedded(html).entries[0].request, undefined);
});

test('unknown arbitrary method, MIME, and finding strings cannot cross into output', () => {
  const report = fixture();
  const secret = 'source-secret-canary';
  report.entries[0].method = secret; report.endpoints[0].method = secret;
  report.entries[0].mimeClass = secret; report.entries[0].findings = [secret, 'slow', 'slow'];
  const html = renderReport(report);
  assert.ok(!html.includes(secret));
  assert.equal(embedded(html).entries[0].method, 'OTHER');
  assert.equal(embedded(html).entries[0].mimeClass, 'unknown');
  assert.deepEqual(embedded(html).entries[0].findings, ['slow']);
});

test('rejects malformed source-controlled identifiers without echoing them', () => {
  for (const change of [r => { r.reportId = 'private-secret-path'; }, r => { r.entries[0].endpointId = '</script>private-secret-path'; }, r => { r.endpoints[0].id = 'private-secret-path'; }]) {
    const report = fixture(); change(report);
    assert.throws(() => renderReport(report), { name: 'TypeError', message: 'Invalid anonymous diagnostic report.' });
  }
});

test('rejects invalid numeric data rather than serializing strings or Infinity', () => {
  for (const value of ['private-secret', NaN, Infinity, -2, Number.MAX_SAFE_INTEGER + 1]) {
    const report = fixture(); report.entries[0].totalMs = value;
    assert.throws(() => renderReport(report), /Invalid anonymous diagnostic report\./);
  }
});

test('preserves unknown timing and body sizes as -1, never rewrites them as zero', () => {
  const report = embedded(renderReport(fixture()));
  assert.equal(report.entries[1].timings.connect, -1);
  assert.equal(report.entries[1].sizes.responseBodyBytes, -1);
});

test('rejects duplicate source indices, invalid status, excessive entries and unsupported schema', () => {
  for (const change of [r => { r.entries[1].sourceEntryIndex = 0; }, r => { r.entries[1].status = 600; }, r => { r.entries[1].status = 1; }, r => { r.entries[1].status = 99; }, r => { r.entries[1].sourceEntryIndex = 0.5; }, r => { r.entries = Array(10001).fill(r.entries[0]); }, r => { r.schemaVersion = 2; }]) {
    const report = fixture(); change(report);
    assert.throws(() => renderReport(report), /Invalid anonymous diagnostic report\./);
  }
});

test('pins the executable script and style content with CSP hashes', () => {
  const html = renderReport(fixture());
  const js = bootstrap(html);
  const styles = html.match(/<style>([\s\S]*?)<\/style>/)[1];
  const hash = s => createHash('sha256').update(s).digest('base64');
  assert.ok(html.includes(hash(js)));
  assert.ok(html.includes(hash(styles)));
  assert.match(html, /connect-src &#39;none&#39;/);
  assert.doesNotMatch(html, /unsafe-inline|unsafe-eval|\bon(?:click|load|error)=/i);
  assert.doesNotThrow(() => new vm.Script(js));
});

test('explains observation limits, relative time and TLS non-additivity', () => {
  const html = renderReport(fixture());
  for (const expected of ['TLS is part of connection time, never added twice', 'does not prove a backend or database problem', 'unknown phases are not treated as zero', 'Relative start', 'proportions hidden', 'Original source order']) assert.ok(html.includes(expected), expected);
});

test('empty diagnostic projection renders without fabricated requests', () => {
  const report = fixture(); report.entries = []; report.endpoints = [];
  Object.keys(report.summary).forEach(key => { report.summary[key] = 0; });
  assert.deepEqual(embedded(renderReport(report)).entries, []);
});

test('rendering is deterministic and does not mutate the supplied report', () => {
  const report = fixture(); const before = JSON.stringify(report);
  assert.equal(renderReport(report), renderReport(report));
  assert.equal(JSON.stringify(report), before);
});

test('renders the actual analyzer schema without carrying source text', () => {
  const har = { log: { version: '1.2', entries: [{
    startedDateTime: '2026-10-15T00:00:00.000Z', time: 3000,
    request: { url: 'https://private-canary.example/users/personal-canary?token=secret-canary', method: 'GET', headers: [{ name: 'Authorization', value: 'secret-canary' }], bodySize: 0, headersSize: 50 },
    response: { status: 503, bodySize: 120, headersSize: 20, content: { mimeType: 'application/json', size: 120, text: 'body-canary' } },
    timings: { blocked: 0, dns: 10, connect: 100, ssl: 80, send: 10, wait: 2800, receive: 80 },
  }] } };
  const report = analyzeHar(new TextEncoder().encode(JSON.stringify(har)));
  const html = renderReport(report);
  assert.equal(embedded(html).reportId, report.reportId);
  assert.equal(embedded(html).entries[0].sourceEntryIndex, 0);
  assert.ok(!html.includes('canary'));
  assert.ok(!html.includes('2026-10-15'));
});
