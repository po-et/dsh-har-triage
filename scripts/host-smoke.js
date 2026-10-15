import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Context } from '@deepseek-ai/cordis';
import Loader from '@deepseek-ai/cordis-plugin-loader';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import ToolRuntime from '@deepseek-ai/dsh-tools';
import LocalFileSystem from '@deepseek-ai/dsh-fs-local';
import SessionProjectionRegistry from '@deepseek-ai/dsh-session-projection';
import SandboxPolicyService from '@deepseek-ai/dsh-sandbox-policy';
import { parse } from 'yaml';
import * as HarTriage from '../src/plugin.js';

// Synthetic only: these secrets are deliberate witnesses, never real traffic.
export function syntheticHar(count = 1) {
  return JSON.stringify({ log: { version: '1.2', creator: { name: 'synthetic-fixture', version: '1' },
    entries: Array.from({ length: count }, (_, index) => ({
      startedDateTime: new Date(Date.UTC(2026, 9, 15, 0, 0, 0, index * 100)).toISOString(),
      time: 2500,
      request: { method: 'GET', url: 'https://HAR_SECRET_CANARY.test/private?token=HAR_SECRET_CANARY',
        bodySize: 0, headersSize: 100, headers: [{ name: 'Authorization', value: 'HAR_SECRET_CANARY' }] },
      response: { status: 503, statusText: 'HAR_SECRET_CANARY', bodySize: 32, headersSize: 80,
        content: { size: 32, mimeType: 'application/json', text: 'HAR_SECRET_CANARY' } },
      timings: { blocked: 0, dns: 10, connect: 50, ssl: 30, send: 10, wait: 2400, receive: 30 }
    })) } });
}

// Real services and dispatch. No LLM, network traffic or CLI Profile boot is involved.
export async function createHost(workspace, { mode = 'workspace-write', bundle = false } = {}) {
  const ctx = new Context();
  try {
    await ctx.plugin(SystemPrompt);
    await ctx.plugin(ToolRuntime, { mode: 'native' });
    await ctx.plugin(SessionProjectionRegistry);
    await ctx.plugin(SandboxPolicyService, { mode, workspaceRoot: workspace });
    await ctx.plugin(LocalFileSystem, { cwd: workspace });
    let fiber;
    if (bundle) {
      await ctx.plugin(Loader, { baseUrl: new URL('../package.json', import.meta.url).href });
      if (!ctx.loader.internal) throw new Error('Bundle smoke requires node --expose-internals');
      const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
      const patch = parse(await readFile(new URL(`../${manifest.dsh.bundle.patch}`, import.meta.url), 'utf8'));
      assert.equal(patch.length, 1);
      assert.equal(patch[0].insert.length, 1);
      assert.equal(patch[0].insert[0].name, manifest.name);
      await ctx.loader.root.update(patch[0].insert);
      await ctx.loader.await();
      fiber = ctx.loader.resolve(patch[0].insert[0].id).fiber;
    } else {
      fiber = await ctx.plugin(HarTriage);
    }
    assert.ok(ctx.tools.get('har_triage'), 'host registered HAR Triage');
    return { ctx, fiber };
  } catch (error) {
    await ctx.fiber.dispose();
    throw error;
  }
}

let callSequence = 0;
export function dispatch(ctx, name, args, signal = new AbortController().signal) {
  return ctx.tools.execute({ callId: `har-smoke-${++callSequence}`, name, arguments: args, signal });
}

export async function runSmoke() {
  const workspace = await mkdtemp(join(tmpdir(), 'har-triage-host-'));
  const input = syntheticHar();
  await writeFile(join(workspace, 'capture.har'), input);
  const { ctx, fiber } = await createHost(workspace, { bundle: true });
  try {
    const args = { input: 'capture.har', outputDir: 'reports' };
    const result = await dispatch(ctx, 'har_triage', args);
    assert.equal(result.isError, false, JSON.stringify(result));
    assert.equal(result.value.summary.requests5xx, 1);
    assert.equal(result.value.summary.slowRequests, 1);
    assert.equal(result.value.evidence.length, 1);
    assert.deepEqual(result.value.evidence[0].findings, ['http-server-error', 'slow', 'wait-dominant']);
    const report = JSON.parse(await readFile(result.value.paths.json, 'utf8'));
    const html = await readFile(result.value.paths.html, 'utf8');
    assert.equal(report.reportId, result.value.reportId);
    assert.ok(html.includes(report.reportId));
    for (const output of [JSON.stringify(result), JSON.stringify(report), html]) {
      assert.ok(!output.includes('HAR_SECRET_CANARY'), 'capture secrets must not reach artifacts or Agent output');
    }
    assert.equal(await readFile(join(workspace, 'capture.har'), 'utf8'), input);
    const collision = await dispatch(ctx, 'har_triage', args);
    assert.equal(collision.isError, true);
    assert.match(JSON.stringify(collision.content), /never overwrites/);
    await fiber.dispose();
    assert.equal(ctx.tools.get('har_triage'), undefined, 'disposing the loaded bundle unregisters its tool');
    const versions = {};
    for (const packageName of ['cordis', 'dsh-tools', 'dsh-fs', 'dsh-sandbox-policy']) {
      const manifest = await import(`@deepseek-ai/${packageName}/package.json`, { with: { type: 'json' } });
      versions[packageName] = manifest.default.version;
    }
    return { ok: true, host: 'real Cordis Context, Loader, ToolRuntime, LocalFileSystem, SandboxPolicyService',
      bundle: 'manifest dsh.bundle patch imported by the real Cordis Loader',
      profileBoot: 'CLI Profile installation and boot are outside this smoke',
      versions, workspace, paths: result.value.paths, summary: result.value.summary };
  } finally { await ctx.fiber.dispose(); }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  console.log(JSON.stringify(await runSmoke(), null, 2));
}
