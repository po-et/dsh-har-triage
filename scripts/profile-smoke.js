import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const project = fileURLToPath(new URL('..', import.meta.url));
const script = fileURLToPath(import.meta.url);

function run(command, args, options) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 120_000, maxBuffer: 2 ** 20, ...options });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${command} failed:\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

async function dispatchProfile(installation, workspace) {
  process.chdir(workspace);
  const version = JSON.parse(await readFile(join(installation, 'package.json'), 'utf8')).version;
  const { runProfile } = await import(pathToFileURL(join(installation, 'lib/profile-boot.js')));
  const { createLaunchEnvironmentSnapshot } = await import(pathToFileURL(join(dirname(installation), 'dsh-launch-environment/lib/index.js')));
  const { ctx } = await runProfile({ profile: 'har-smoke', patchFiles: [], args: [],
    environment: createLaunchEnvironmentSnapshot([{ source: 'process', values: process.env }]) });
  try {
    assert.ok(ctx.tools.get('har_triage'), 'packed plugin must register in the real profile');
    const execute = async args => {
      const callId = `har-profile-${args.outputDir}`;
      const signal = new AbortController().signal;
      if (version === '0.2.2-alpha.2') {
        // 0.2.2 delegates raw call batches to the configured tool executor.
        const batch = await ctx.tools.execute({ calls: [{ id: callId, name: 'har_triage', arguments: JSON.stringify(args) }], signal });
        assert.equal(batch.results.length, 1);
        assert.equal(batch.results[0].callId, callId);
        return batch.results[0].result;
      }
      return ctx.tools.execute({ callId, name: 'har_triage', arguments: args, signal });
    };
    const input = await readFile(join(workspace, 'capture.har'), 'utf8');
    const args = { input: 'capture.har', outputDir: 'reports' };
    const result = await execute(args);
    assert.equal(result.isError, false, JSON.stringify(result));
    assert.equal(result.value.summary.requests5xx, 1);
    const html = await readFile(result.value.paths.html, 'utf8');
    const json = await readFile(result.value.paths.json, 'utf8');
    assert.equal(JSON.parse(json).reportId, result.value.reportId);
    for (const output of [JSON.stringify(result), html, json]) assert.ok(!output.includes('HAR_SECRET_CANARY'));
    assert.equal(await readFile(join(workspace, 'capture.har'), 'utf8'), input);
    assert.equal((await execute(args)).isError, true, 'existing evidence must not be overwritten');
    const escape = await execute({ input: '../outside.har', outputDir: 'escape' });
    assert.equal(escape.isError, true, 'reads outside the session workspace must fail');
    const pluginVersion = JSON.parse(await readFile(join(project, 'package.json'), 'utf8')).version;
    console.log(JSON.stringify({ ok: true, harness: version, plugin: pluginVersion, profileBoot: true, tool: 'har_triage',
      checks: ['packaged CLI install', 'real profile registration and dispatch', 'source preserved',
        'canary absent from output', 'overwrite refused', 'workspace escape refused'],
      workspace, paths: result.value.paths }, null, 2));
  } finally { await ctx.fiber.dispose(); }
}

async function main() {
  const requested = process.argv[2] ?? process.env.DSH_INSTALL;
  assert.ok(requested, 'Pass the absolute @deepseek-ai/dsh package directory (or set DSH_INSTALL)');
  const installation = resolve(requested);
  const hostManifest = JSON.parse(await readFile(join(installation, 'package.json'), 'utf8'));
  assert.equal(hostManifest.name, '@deepseek-ai/dsh');
  assert.ok(['0.2.1-rc.2', '0.2.1-rc.3', '0.2.1-rc.4', '0.2.2-alpha.2'].includes(hostManifest.version), 'use a supported host version');
  const directory = await mkdtemp(join(tmpdir(), 'har-triage-profile-'));
  const workspace = join(directory, 'workspace');
  const home = join(directory, 'dsh-home');
  const profile = join(home, 'profiles/har-smoke');
  await mkdir(workspace);
  const { syntheticHar } = await import('./host-smoke.js');
  await writeFile(join(workspace, 'capture.har'), syntheticHar());
  await writeFile(join(directory, 'outside.har'), syntheticHar());
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, DSH_HOME: home,
    DSH_AGENTS_HOME: join(directory, 'agents'), DSH_TELEMETRY_DISABLED: '1', DSH_PERMISSION_MODE: 'workspace-write' };
  const [{ filename }] = JSON.parse(run('npm', ['pack', '--pack-destination', directory, '--json'], { cwd: project }));
  const cli = join(installation, 'lib/bin.js');
  run(process.execPath, [cli, 'plugin', '--profile', 'har-smoke', 'add', join(directory, filename)], { cwd: workspace, env });
  const installedManifest = JSON.parse(await readFile(join(profile, 'node_modules/dsh-har-triage/package.json'), 'utf8'));
  const expectedVersion = JSON.parse(await readFile(join(project, 'package.json'), 'utf8')).version;
  assert.equal(installedManifest.version, expectedVersion);
  const tree = run(process.execPath, [cli, '--profile', 'har-smoke', '--dump-config'], { cwd: workspace, env });
  assert.match(tree, /name: dsh-har-triage/);
  // Disable only test-profile HMR so the acceptance process has a bounded lifetime.
  await writeFile(join(profile, 'cordis.patch.yml'), '- id: hmr\n  disabled: true\n');
  console.log(run(process.execPath, ['--expose-internals', script, '--dispatch', installation, workspace], { cwd: workspace, env }));
}

if (process.argv[2] === '--dispatch') await dispatchProfile(process.argv[3], process.argv[4]);
else await main();
