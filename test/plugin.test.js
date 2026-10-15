import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, open, readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHost, dispatch, syntheticHar } from '../scripts/host-smoke.js';
import { MAX_INPUT_BYTES } from '../src/analyze.js';

const args = { input: 'capture.har', outputDir: 'reports' };
const errorText = result => JSON.stringify(result.content);

async function fixture(count = 1) {
  const workspace = await mkdtemp(join(tmpdir(), 'har-triage-plugin-'));
  const source = syntheticHar(count);
  await writeFile(join(workspace, 'capture.har'), source);
  return { workspace, source };
}

test('real tool dispatch publishes canonical reports, preserves source, refuses overwrite and unregisters', async () => {
  const { workspace, source } = await fixture();
  const { ctx, fiber } = await createHost(workspace);
  try {
    const result = await dispatch(ctx, 'har_triage', args);
    assert.equal(result.isError, false, errorText(result));
    assert.equal(result.value.summary.requests5xx, 1);
    assert.equal(result.value.summary.slowRequests, 1);
    assert.equal(result.value.evidence[0].sourceEntryIndex, 0);
    const data = await readFile(result.value.paths.json, 'utf8');
    const html = await readFile(result.value.paths.html, 'utf8');
    assert.equal(JSON.parse(data).reportId, result.value.reportId);
    assert.match(html, /<!doctype html>/i);
    for (const output of [data, html, JSON.stringify(result)]) assert.ok(!output.includes('HAR_SECRET_CANARY'));
    const collision = await dispatch(ctx, 'har_triage', args);
    assert.equal(collision.isError, true);
    assert.match(errorText(collision), /never overwrites/);
    assert.equal(await readFile(result.value.paths.json, 'utf8'), data);
    assert.equal(await readFile(result.value.paths.html, 'utf8'), html);
    assert.equal(await readFile(join(workspace, 'capture.har'), 'utf8'), source);
    await fiber.dispose();
    assert.equal(ctx.tools.get('har_triage'), undefined);
  } finally { await ctx.fiber.dispose(); }
});

test('read-only policy denies publication before any artifacts are created', async () => {
  const { workspace } = await fixture();
  const { ctx } = await createHost(workspace, { mode: 'read-only' });
  try {
    const result = await dispatch(ctx, 'har_triage', args);
    assert.equal(result.isError, true);
    assert.match(errorText(result), /workspace-write permission/);
    assert.deepEqual(await readdir(workspace), ['capture.har']);
  } finally { await ctx.fiber.dispose(); }
});

test('realpath containment rejects outside reads and symlinked input/output escapes even in full-access mode', async () => {
  const { workspace } = await fixture();
  const outside = await mkdtemp(join(tmpdir(), 'har-triage-outside-'));
  await writeFile(join(outside, 'capture.har'), syntheticHar());
  await symlink(outside, join(workspace, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  const { ctx } = await createHost(workspace, { mode: 'danger-full-access' });
  try {
    for (const candidate of [
      { ...args, input: join(outside, 'capture.har') },
      { ...args, input: 'escape/capture.har' },
      { ...args, outputDir: 'escape/reports' },
      { ...args, outputDir: '../escaped-report' }
    ]) {
      const result = await dispatch(ctx, 'har_triage', candidate);
      assert.equal(result.isError, true);
      assert.match(errorText(result), /session workspace/);
    }
    assert.deepEqual(await readdir(outside), ['capture.har']);
    assert.ok(!(await readdir(workspace)).includes('reports'));
  } finally { await ctx.fiber.dispose(); }
});

test('schema, path and threshold validation fail without writes or reflective HAR errors', async () => {
  const { workspace } = await fixture();
  const { ctx } = await createHost(workspace);
  try {
    for (const candidate of [
      { outputDir: 'reports' }, { ...args, input: 1 }, { ...args, input: '' },
      { ...args, outputDir: '\0' }, { ...args, slowMs: '2000' }, { ...args, slowMs: 0 },
      { ...args, slowMs: -1 }, { ...args, outputDir: 'capture.har' }, { ...args, input: '.' }
    ]) assert.equal((await dispatch(ctx, 'har_triage', candidate)).isError, true);
    await writeFile(join(workspace, 'bad.har'), '{"RAW_SECRET_JSON":');
    const invalid = await dispatch(ctx, 'har_triage', { ...args, input: 'bad.har' });
    assert.equal(invalid.isError, true);
    assert.ok(!errorText(invalid).includes('RAW_SECRET_JSON'));
    assert.ok(!(await readdir(workspace)).includes('reports'));
  } finally { await ctx.fiber.dispose(); }
});

test('the real filesystem refuses oversized input without producing reports', async () => {
  const { workspace } = await fixture();
  const handle = await open(join(workspace, 'large.har'), 'wx');
  try { await handle.truncate(MAX_INPUT_BYTES + 1); } finally { await handle.close(); }
  const { ctx } = await createHost(workspace);
  try {
    const result = await dispatch(ctx, 'har_triage', { ...args, input: 'large.har' });
    assert.equal(result.isError, true);
    assert.ok(!(await readdir(workspace)).includes('reports'));
  } finally { await ctx.fiber.dispose(); }
});

test('Agent evidence is capped at 20 and the complete allowlisted report remains local', async () => {
  const { workspace } = await fixture(25);
  const { ctx } = await createHost(workspace);
  try {
    const result = await dispatch(ctx, 'har_triage', args);
    assert.equal(result.isError, false, errorText(result));
    assert.equal(result.value.evidence.length, 20);
    assert.equal(result.value.omittedEvidenceCount, 5);
    assert.equal(result.value.summary.analyzedEntries, 25);
    assert.equal(result.value.evidence.at(-1).sourceEntryIndex, 19);
    assert.equal(JSON.parse(await readFile(result.value.paths.json, 'utf8')).entries.length, 25);
    assert.ok(!JSON.stringify(result).includes('HAR_SECRET_CANARY'));
  } finally { await ctx.fiber.dispose(); }
});

test('pre-cancellation and cancellation immediately after bounded reading prevent publication', async () => {
  const { workspace } = await fixture();
  const { ctx } = await createHost(workspace);
  try {
    const cancelled = new AbortController();
    cancelled.abort();
    assert.equal((await dispatch(ctx, 'har_triage', args, cancelled.signal)).isError, true);
    const controller = new AbortController();
    const read = ctx.fs.readBytes.bind(ctx.fs);
    let readCount = 0;
    ctx.fs.readBytes = async (target, signal, limit) => {
      assert.equal(signal, controller.signal);
      assert.equal(limit, MAX_INPUT_BYTES);
      const content = await read(target, signal, limit);
      readCount++;
      controller.abort();
      return content;
    };
    assert.equal((await dispatch(ctx, 'har_triage', args, controller.signal)).isError, true);
    assert.equal(readCount, 1);
    assert.deepEqual(await readdir(workspace), ['capture.har']);
  } finally { await ctx.fiber.dispose(); }
});

test('exclusive publication preserves a concurrent creator that appears after stat preflight', async () => {
  for (const extension of ['.json', '.html']) {
    const { workspace } = await fixture();
    const { ctx } = await createHost(workspace);
    const write = ctx.fs.writeText.bind(ctx.fs);
    let racedPath;
    ctx.fs.writeText = async (target, ...values) => {
      assert.deepEqual(values[1], { kind: 'createIfAbsent' });
      if (target.displayPath.endsWith(extension)) {
        await mkdir(join(workspace, 'reports'), { recursive: true });
        racedPath = target.displayPath;
        await writeFile(racedPath, 'concurrent-owner', { flag: 'wx' });
      }
      return write(target, ...values);
    };
    try {
      const result = await dispatch(ctx, 'har_triage', args);
      assert.equal(result.isError, true);
      assert.equal(await readFile(racedPath, 'utf8'), 'concurrent-owner');
      assert.equal((await readdir(join(workspace, 'reports'))).length, extension === '.html' ? 2 : 1);
    } finally { await ctx.fiber.dispose(); }
  }
});

test('failed or cancelled second publication keeps the already-created JSON, never deleting it', async () => {
  for (const cancel of [false, true]) {
    const { workspace } = await fixture();
    const { ctx } = await createHost(workspace);
    const write = ctx.fs.writeText.bind(ctx.fs);
    const controller = new AbortController();
    ctx.fs.writeText = async (target, ...values) => {
      if (target.displayPath.endsWith('.html') && !cancel) throw new Error('backend failure');
      const result = await write(target, ...values);
      if (cancel) controller.abort();
      return result;
    };
    try {
      const result = await dispatch(ctx, 'har_triage', args, controller.signal);
      assert.equal(result.isError, true);
      if (!cancel) assert.match(errorText(result), /JSON evidence was saved.*HTML publication failed/);
      const artifacts = await readdir(join(workspace, 'reports'));
      assert.equal(artifacts.length, 1);
      assert.ok(artifacts[0].endsWith('.json'));
      assert.equal(JSON.parse(await readFile(join(workspace, 'reports', artifacts[0]), 'utf8')).summary.requests5xx, 1);
    } finally { await ctx.fiber.dispose(); }
  }
});
