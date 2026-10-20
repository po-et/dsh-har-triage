import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, mkdir, stat, access, truncate } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_INPUT_BYTES } from '../src/analyze.js';

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const canary = 'CLI_SECRET_CANARY_f78e251';

function capture() {
  const entry = (time, status, startedDateTime) => ({
    startedDateTime, time,
    request: {
      method: 'GET', url: `https://${canary}.test/private-${canary}?token=${canary}`,
      headers: [{ name: 'Authorization', value: canary }],
      cookies: [{ name: 'session', value: canary }], bodySize: 0, headersSize: 80,
    },
    response: {
      status, statusText: canary, bodySize: 120, headersSize: 40,
      headers: [{ name: 'Set-Cookie', value: canary }],
      content: { size: 120, mimeType: 'application/json', text: canary },
    },
    timings: { blocked: 0, dns: 0, connect: 0, ssl: 0, send: 0, wait: time - 10, receive: 10 },
    _initiator: { url: canary }, comment: canary,
  });
  return { log: {
    version: '1.2', creator: { name: canary, version: canary },
    entries: [
      entry(3000, 503, '2026-10-15T00:00:00.000Z'),
      { request: { url: `data:text/plain,${canary}` } },
      entry(100, 200, '2026-10-15T00:00:03.000Z'),
    ],
  } };
}

async function temporaryCapture(value = JSON.stringify(capture())) {
  // Keep these tiny test artifacts for inspection; never recursively remove files.
  const directory = await mkdtemp(join(tmpdir(), 'har-triage-cli-test-'));
  const input = join(directory, 'capture.har');
  await writeFile(input, value, { mode: 0o600 });
  return { directory, input, out: join(directory, 'report') };
}

function run(args, options = {}) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8', timeout: 2000, maxBuffer: 1024 * 1024, ...options,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, 'CLI must exit without timing out or being killed');
  return result;
}

async function absent(path) {
  await assert.rejects(access(path), { code: 'ENOENT' });
}

test('real CLI --help and no-argument usage complete without reading a capture', () => {
  for (const args of [['--help'], []]) {
    const result = run(args);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /HAR Triage — offline network evidence/);
    assert.match(result.stdout, /--out new-report-directory/);
    assert.equal(result.stderr, '');
  }
});

test('real CLI writes anonymous JSON and standalone HTML without changing source bytes', async () => {
  const paths = await temporaryCapture();
  const original = await readFile(paths.input);
  const result = run([paths.input, '--out', paths.out]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const receipt = JSON.parse(result.stdout);
  const jsonBytes = await readFile(join(paths.out, 'report.json'));
  const html = await readFile(join(paths.out, 'report.html'), 'utf8');
  const report = JSON.parse(jsonBytes);
  assert.equal(receipt.report, join(paths.out, 'report.html'));
  assert.equal(receipt.data, join(paths.out, 'report.json'));
  assert.equal(receipt.reportId, report.reportId);
  assert.deepEqual(receipt.summary, report.summary);
  assert.deepEqual(report.entries.map(entry => entry.sourceEntryIndex), [0, 2]);
  assert.equal(report.summary.filteredEntries, 1);
  assert.equal(report.summary.requests5xx, 1);
  assert.equal(report.summary.slowRequests, 1);
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /id="status-filter"/);
  for (const output of [result.stdout, result.stderr, jsonBytes.toString('utf8'), html]) {
    assert.ok(!output.includes(canary));
    assert.ok(!output.includes('2026-10-15T00:00:00.000Z'));
  }
  assert.deepEqual(await readFile(paths.input), original);
  if (process.platform !== 'win32') {
    assert.equal((await stat(paths.out)).mode & 0o077, 0);
    assert.equal((await stat(join(paths.out, 'report.json'))).mode & 0o077, 0);
    assert.equal((await stat(join(paths.out, 'report.html'))).mode & 0o077, 0);
  }
});

test('real CLI preserves the JSON content class of an Ollama NDJSON capture in both reports', async () => {
  const har = capture();
  har.log.entries[0].response.content.mimeType = 'application/x-ndjson; charset=utf-8';
  har.log.entries[0].response.content.text = `{"response":"${canary}","done":false}\n{"done":true}\n`;
  const paths = await temporaryCapture(JSON.stringify(har));
  const original = await readFile(paths.input);
  const result = run([paths.input, '--out', paths.out]);
  assert.equal(result.status, 0, result.stderr);
  const json = await readFile(join(paths.out, 'report.json'), 'utf8');
  const html = await readFile(join(paths.out, 'report.html'), 'utf8');
  const embedded = JSON.parse(html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1]);
  assert.equal(JSON.parse(json).entries[0].mimeClass, 'json');
  assert.equal(embedded.entries[0].mimeClass, 'json');
  for (const output of [result.stdout, result.stderr, json, html]) assert.ok(!output.includes(canary));
  assert.deepEqual(await readFile(paths.input), original);
});

test('real CLI carries contradictory TLS evidence into JSON and HTML without changing source bytes', async () => {
  const har = capture();
  har.log.entries = [har.log.entries[0]];
  har.log.entries[0].time = 100;
  har.log.entries[0].response.status = 200;
  har.log.entries[0].timings = { connect: -1, ssl: 250, send: 0, wait: 50, receive: 50 };
  const paths = await temporaryCapture(JSON.stringify(har));
  const original = await readFile(paths.input);
  const result = run([paths.input, '--out', paths.out]);
  assert.equal(result.status, 0, result.stderr);
  const json = await readFile(join(paths.out, 'report.json'), 'utf8');
  const html = await readFile(join(paths.out, 'report.html'), 'utf8');
  const report = JSON.parse(json);
  const embedded = JSON.parse(html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1]);
  for (const projection of [report, embedded]) {
    assert.deepEqual(projection.entries[0].findings, ['timing-mismatch']);
    assert.equal(projection.entries[0].timings.connect, -1);
    assert.equal(projection.entries[0].timings.ssl, 250);
  }
  for (const output of [result.stdout, result.stderr, json, html]) assert.ok(!output.includes(canary));
  assert.deepEqual(await readFile(paths.input), original);
});

test('real CLI refuses an existing output directory and preserves its files', async () => {
  const paths = await temporaryCapture();
  await mkdir(paths.out);
  const sentinelJson = 'existing JSON must stay intact';
  const sentinelHtml = 'existing HTML must stay intact';
  await writeFile(join(paths.out, 'report.json'), sentinelJson);
  await writeFile(join(paths.out, 'report.html'), sentinelHtml);
  const original = await readFile(paths.input);
  const result = run([paths.input, '--out', paths.out]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /EEXIST|already exists/i);
  assert.equal(result.stdout, '');
  assert.equal(await readFile(join(paths.out, 'report.json'), 'utf8'), sentinelJson);
  assert.equal(await readFile(join(paths.out, 'report.html'), 'utf8'), sentinelHtml);
  assert.deepEqual(await readFile(paths.input), original);
});

test('real CLI refuses to use the original input file as the output directory', async () => {
  const paths = await temporaryCapture();
  const original = await readFile(paths.input);
  const result = run([paths.input, '--out', paths.input]);
  assert.equal(result.status, 1);
  assert.deepEqual(await readFile(paths.input), original);
});

test('real CLI reports invalid JSON without echoing source text or parser excerpts', async () => {
  const paths = await temporaryCapture(`{"private":"${canary}",`);
  const original = await readFile(paths.input);
  const result = run([paths.input, '--out', paths.out]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.trim(), 'HAR input is not valid UTF-8 JSON.');
  assert.ok(!result.stderr.includes(canary));
  assert.ok(!result.stderr.includes(paths.input));
  await absent(paths.out);
  assert.deepEqual(await readFile(paths.input), original);
});

test('real CLI reports invalid UTF-8 with the same fixed non-leaking message', async () => {
  const paths = await temporaryCapture(Buffer.from([0xff, 0xfe, 0x7b]));
  const result = run([paths.input, '--out', paths.out]);
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), 'HAR input is not valid UTF-8 JSON.');
  await absent(paths.out);
});

test('real CLI validates arguments without echoing unknown flags or values', async () => {
  const paths = await temporaryCapture();
  const invalidArgs = [
    [paths.input, '--unknown-' + canary, canary],
    [paths.input, '--out'],
    [paths.input, '--out', '--slow-ms', '100'],
    [paths.input, '--out', paths.out, '--out', paths.out],
    [paths.input, '--out', paths.out, '--slow-ms', '100', '--slow-ms', '200'],
    [paths.input, '--out', paths.out, 'extra-position', canary],
  ];
  for (const args of invalidArgs) {
    const result = run(args);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr.trim(), 'Use --out DIRECTORY and at most one --slow-ms NUMBER');
    assert.ok(!result.stderr.includes(canary));
    await absent(paths.out);
  }
});

test('real CLI rejects missing input and required output arguments', async () => {
  const paths = await temporaryCapture();
  const noInput = run(['--out', paths.out]);
  assert.equal(noInput.status, 1);
  assert.match(noInput.stderr, /HAR Triage/);
  const noOutput = run([paths.input]);
  assert.equal(noOutput.status, 1);
  assert.equal(noOutput.stderr.trim(), '--out is required');
  const slowOnly = run([paths.input, '--slow-ms', '100']);
  assert.equal(slowOnly.status, 1);
  assert.equal(slowOnly.stderr.trim(), '--out is required');
  await absent(paths.out);
});

test('real CLI --slow-ms changes the actual analysis threshold', async () => {
  const paths = await temporaryCapture();
  const result = run([paths.input, '--slow-ms', '50', '--out', paths.out]);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(await readFile(join(paths.out, 'report.json'), 'utf8'));
  assert.equal(report.settings.slowMs, 50);
  assert.equal(report.summary.slowRequests, 2);
  assert.ok(report.entries.every(entry => entry.findings.includes('slow')));
  assert.equal(JSON.parse(result.stdout).summary.slowRequests, 2);
});

test('real CLI rejects invalid slow thresholds before creating output', async () => {
  const paths = await temporaryCapture();
  for (const value of ['0', '-1', 'NaN', 'Infinity', 'not-a-number', String(Number.MAX_SAFE_INTEGER + 1)]) {
    const result = run([paths.input, '--out', paths.out, '--slow-ms', value]);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr.trim(), 'Analysis options are invalid.');
    await absent(paths.out);
  }
});

test('real CLI rejects non-file input and oversized regular files without output', async () => {
  const paths = await temporaryCapture();
  const directoryResult = run([paths.directory, '--out', paths.out]);
  assert.equal(directoryResult.status, 1);
  assert.match(directoryResult.stderr, /regular file|EISDIR/);
  await absent(paths.out);
  const oversized = join(paths.directory, 'oversized.har');
  await writeFile(oversized, ' ');
  await truncate(oversized, MAX_INPUT_BYTES + 1);
  const result = run([oversized, '--out', paths.out]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /regular file no larger than 16 MiB/);
  await absent(paths.out);
});

test('real CLI reports a missing capture as failure without creating a report', async () => {
  const paths = await temporaryCapture();
  const result = run([join(paths.directory, 'missing.har'), '--out', paths.out]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  await absent(paths.out);
});

test('real CLI rejects a POSIX FIFO immediately instead of waiting for a writer', {
  skip: process.platform === 'win32',
}, async () => {
  const paths = await temporaryCapture();
  const fifo = join(paths.directory, 'capture-pipe.har');
  const made = spawnSync('mkfifo', [fifo], { encoding: 'utf8', timeout: 2000 });
  assert.equal(made.error, undefined, made.error?.message);
  assert.equal(made.status, 0, made.stderr);
  const result = run([fifo, '--out', paths.out]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /regular file no larger than 16 MiB/);
  await absent(paths.out);
});
