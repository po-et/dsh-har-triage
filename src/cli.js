#!/usr/bin/env node
import { open, mkdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { analyzeHar, MAX_INPUT_BYTES } from './analyze.js';
import { renderReport } from './report.js';

const usage = `HAR Triage — offline network evidence

  har-triage capture.har --out new-report-directory [--slow-ms 2000]

Reads a HAR file; never sends requests or changes the source.
The output directory must not already exist.
Reports omit URLs, headers, bodies, query values and absolute timestamps.
Use the original zero-based HAR entry index to look up endpoint details locally.
`;

async function readBounded(path) {
  // A FIFO must reach the regular-file check without waiting for a writer.
  const handle = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_INPUT_BYTES) throw new Error('HAR input must be a regular file no larger than 16 MiB');
    const chunks = [];
    let total = 0;
    while (total <= MAX_INPUT_BYTES) {
      const chunk = Buffer.alloc(Math.min(65536, MAX_INPUT_BYTES + 1 - total));
      const { bytesRead } = await handle.read(chunk);
      if (!bytesRead) break;
      chunks.push(chunk.subarray(0, bytesRead)); total += bytesRead;
    }
    if (total > MAX_INPUT_BYTES) throw new Error('HAR input grew beyond the 16 MiB limit');
    return Buffer.concat(chunks);
  } finally { await handle.close(); }
}

export async function main(argv = process.argv.slice(2)) {
  if (!argv.length || argv.includes('--help')) { console.log(usage); return; }
  const [input, ...flags] = argv;
  if (input.startsWith('--')) throw new Error(usage);
  let out; let slowMs;
  const seen = new Set();
  for (let index = 0; index < flags.length; index += 2) {
    const flag = flags[index]; const value = flags[index + 1];
    if (!['--out', '--slow-ms'].includes(flag) || value === undefined || value.startsWith('--') || seen.has(flag)) {
      throw new Error('Use --out DIRECTORY and at most one --slow-ms NUMBER');
    }
    seen.add(flag);
    if (flag === '--out') out = resolve(value);
    else slowMs = Number(value);
  }
  if (!out) throw new Error('--out is required');
  const report = analyzeHar(await readBounded(input), { slowMs });
  const html = renderReport(report);
  await mkdir(out, { mode: 0o700 });
  try {
    await writeFile(join(out, 'report.json'), `${JSON.stringify(report)}\n`, { flag: 'wx', mode: 0o600 });
    await writeFile(join(out, 'report.html'), html, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    throw new Error('Could not finish the report; partial output was retained. Retry with a fresh directory.', { cause: error });
  }
  console.log(JSON.stringify({ report: join(out, 'report.html'), data: join(out, 'report.json'), reportId: report.reportId, summary: report.summary }, null, 2));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
