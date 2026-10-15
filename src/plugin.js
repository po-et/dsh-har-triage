import { defineTool } from '@deepseek-ai/dsh-tools';
import { FsError } from '@deepseek-ai/dsh-fs';
import { analyzeHar, MAX_INPUT_BYTES } from './analyze.js';
import { renderReport } from './report.js';

export const name = 'har-triage';
export const inject = ['tools', 'fs', 'sandboxPolicy'];
const requiredString = { type: 'string', required: true };

function nonempty(value) {
  if (typeof value !== 'string' || !value.trim() || value.includes('\0')) {
    throw new Error('Paths must be non-empty strings without NUL characters');
  }
}

async function target(ctx, workspace, cwd, path, signal) {
  nonempty(path);
  const result = await ctx.fs.resolve(path, { cwd, signal });
  if (!ctx.fs.contains(workspace, result)) {
    throw new FsError('HAR Triage only accesses the session workspace', 'FS_SANDBOX_DENIED');
  }
  return result;
}

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'har_triage',
    description: 'Read a browser HAR file without sending requests or changing it. Create new offline HTML and JSON diagnostic reports in the session workspace. Reports omit URLs, headers, query values, bodies and absolute timestamps; requests use endpoint aliases and original zero-based HAR entry indexes. Evidence describes observations, not proven root causes.',
    parameters: {
      input: { ...requiredString, description: 'Path to the HAR JSON file inside the session workspace' },
      outputDir: { ...requiredString, description: 'Destination directory for new reports inside the session workspace' },
      slowMs: { type: 'number', description: 'Slow-request threshold in milliseconds, default 2000' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          reportId: requiredString,
          paths: {
            type: 'object', required: true, additionalProperties: false,
            properties: { json: requiredString, html: requiredString },
          },
          summary: { type: 'json', required: true },
          evidence: { type: 'json', required: true },
          omittedEvidenceCount: { type: 'integer', required: true },
          notice: requiredString,
        },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    presentCall: args => ({ card: 'generic', title: 'Inspect HAR evidence', kind: 'read', locations: [{ path: args.input }] }),
    async execute(args, exec) {
      exec.signal.throwIfAborted();
      const policy = ctx.sandboxPolicy.resolve({ session: exec.agent?.session });
      if (!['workspace-write', 'danger-full-access'].includes(policy.mode)) {
        throw new FsError('HAR report creation requires workspace-write permission', 'FS_SANDBOX_DENIED');
      }
      const workspace = await ctx.fs.resolve(policy.workspaceRoot, { signal: exec.signal });
      if ((await ctx.fs.stat(workspace, exec.signal))?.type !== 'directory') {
        throw new FsError('The session workspace must exist', 'FS_NOT_DIRECTORY');
      }
      const cwd = ctx.fs.processPath(workspace);
      const input = await target(ctx, workspace, cwd, args.input, exec.signal);
      if ((await ctx.fs.stat(input, exec.signal))?.type !== 'file') {
        throw new FsError('HAR input must be a regular file', 'FS_NOT_REGULAR_FILE');
      }
      const directory = await target(ctx, workspace, cwd, args.outputDir, exec.signal);
      const directoryInfo = await ctx.fs.stat(directory, exec.signal);
      if (directoryInfo && directoryInfo.type !== 'directory') {
        throw new FsError('outputDir must be a directory', 'FS_NOT_DIRECTORY');
      }
      const bytes = await ctx.fs.readBytes(input, exec.signal, MAX_INPUT_BYTES);
      const report = analyzeHar(bytes, { slowMs: args.slowMs, signal: exec.signal });
      const json = await target(ctx, workspace, ctx.fs.processPath(directory), `${report.reportId}.json`, exec.signal);
      const html = await target(ctx, workspace, ctx.fs.processPath(directory), `${report.reportId}.html`, exec.signal);
      if (await ctx.fs.stat(json, exec.signal) || await ctx.fs.stat(html, exec.signal)) {
        throw new FsError('HAR Triage never overwrites an existing report', 'FS_NOT_OBSERVED');
      }
      const reportHtml = renderReport(report);
      exec.signal.throwIfAborted();
      await ctx.fs.writeText(json, `${JSON.stringify(report)}\n`, { kind: 'createIfAbsent' }, exec.signal, policy);
      try {
        await ctx.fs.writeText(html, reportHtml, { kind: 'createIfAbsent' }, exec.signal, policy);
      } catch (error) {
        throw new Error('JSON evidence was saved, but HTML publication failed. The JSON is retained; retry with a fresh outputDir.', { cause: error });
      }
      const findings = report.entries.filter(entry => entry.findings.length);
      return {
        reportId: report.reportId,
        paths: { json: json.displayPath, html: html.displayPath },
        summary: report.summary, evidence: findings.slice(0, 20),
        omittedEvidenceCount: Math.max(0, findings.length - 20),
        notice: 'Source entry indexes are zero-based. Inspect the original HAR locally for endpoint details. Status 0 and long waits do not prove CORS, authentication failure or a server-side root cause. Report metadata can still identify an application; review before sharing.',
      };
    },
  }));
}
