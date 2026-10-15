import { createHash } from 'node:crypto'

export const MAX_INPUT_BYTES = 16 * 1024 * 1024
export const MAX_ENTRIES = 10_000

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'])
const PHASES = ['blocked', 'dns', 'connect', 'ssl', 'send', 'wait', 'receive']
const MESSAGES = {
  'invalid-input': 'Expected HAR JSON as UTF-8 bytes.',
  'input-too-large': 'HAR input exceeds the 16 MiB limit.',
  'invalid-json': 'HAR input is not valid UTF-8 JSON.',
  'invalid-har': 'HAR structure or diagnostic values are invalid.',
  'too-many-entries': 'HAR input exceeds the 10000-entry limit.',
  'invalid-options': 'Analysis options are invalid.',
  cancelled: 'HAR analysis was cancelled.'
}

export class HarInputError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES['invalid-har'])
    this.name = 'HarInputError'
    this.code = Object.hasOwn(MESSAGES, code) ? code : 'invalid-har'
  }
}

function fail(code = 'invalid-har') { throw new HarInputError(code) }
function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) }
function checkCancelled(signal) { if (signal?.aborted) fail('cancelled') }

function numeric(value, unknown = false) {
  if (value === undefined && unknown) return -1
  if (typeof value !== 'number' || !Number.isFinite(value) || value > Number.MAX_SAFE_INTEGER ||
      (value < 0 && !(unknown && value === -1))) fail()
  return value === 0 ? 0 : value
}

function add(a, b) { return numeric(a + b) }

function timestamp(value) {
  if (typeof value !== 'string') fail()
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.exec(value)
  if (!match) fail()
  const [, year, month, day, hour, minute, second, zone] = match
  const y = Number(year), m = Number(month), d = Number(day)
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  if (m < 1 || m > 12 || d < 1 || d > days[m - 1] || Number(hour) > 23 ||
      Number(minute) > 59 || Number(second) > 59 ||
      (zone !== 'Z' && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59))) fail()
  const result = Date.parse(value)
  if (!Number.isFinite(result)) fail()
  return result
}

function method(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64 ||
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)) fail()
  const normalized = value.toUpperCase()
  return METHODS.has(normalized) ? normalized : 'OTHER'
}

function mimeClass(value) {
  if (value === undefined || value === '') return 'unknown'
  if (typeof value !== 'string') fail()
  const type = value.split(';', 1)[0].trim().toLowerCase()
  if (/^(?:application|text)\/(?:[a-z0-9!#$&^_.+-]+\+)?json$/.test(type)) return 'json'
  if (type === 'text/html' || type === 'application/xhtml+xml') return 'html'
  if (type === 'text/css') return 'css'
  if (['application/javascript', 'text/javascript', 'application/ecmascript', 'text/ecmascript'].includes(type)) return 'javascript'
  if (/^(?:application|text)\/(?:[a-z0-9!#$&^_.+-]+\+)?xml$/.test(type)) return 'xml'
  for (const category of ['image', 'font', 'audio', 'video']) {
    if (type.startsWith(`${category}/`) && type.length > category.length + 1) return category
  }
  if (type.startsWith('text/') && type.length > 5) return 'text'
  return type ? 'binary' : 'unknown'
}

function projectEntry(source, sourceEntryIndex, slowMs) {
  if (!record(source) || !record(source.request) || typeof source.request.url !== 'string') fail()
  let url
  try { url = new URL(source.request.url) } catch { fail() }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
  if (!record(source.response) || !record(source.timings) || !record(source.response.content)) fail()
  const verb = method(source.request.method)
  const status = source.response.status
  if (!Number.isInteger(status) || (status !== 0 && status < 100) || status > 599) fail()
  const totalMs = numeric(source.time)
  const started = timestamp(source.startedDateTime)
  const timings = Object.fromEntries(PHASES.map(phase => [phase, numeric(source.timings[phase], true)]))
  const sizes = {
    requestBodyBytes: numeric(source.request.bodySize, true),
    responseBodyBytes: numeric(source.response.bodySize, true),
    responseContentBytes: numeric(source.response.content.size, true),
    requestHeadersBytes: numeric(source.request.headersSize, true),
    responseHeadersBytes: numeric(source.response.headersSize, true)
  }
  for (const size of Object.values(sizes)) if (!Number.isInteger(size)) fail()
  const findings = []
  if (status === 0) findings.push('network-unavailable')
  else if (status >= 500) findings.push('http-server-error')
  else if (status >= 400) findings.push('http-client-error')
  if (totalMs >= slowMs) {
    findings.push('slow')
    if (totalMs > 0 && timings.wait / totalMs >= 0.5) findings.push('wait-dominant')
  }
  // HAR connect already includes TLS. Adding ssl here would double-count it.
  const knownTotal = PHASES.filter(phase => phase !== 'ssl')
    .reduce((sum, phase) => add(sum, Math.max(0, timings[phase])), 0)
  if (knownTotal > totalMs + Math.max(1, totalMs * 0.01) ||
      (timings.connect >= 0 && timings.ssl > timings.connect + 1)) findings.push('timing-mismatch')
  return {
    started,
    endpointKey: JSON.stringify([source.request.method.toUpperCase(), url.origin, url.pathname]),
    entry: {
      sourceEntryIndex, endpointId: '', method: verb, status, startOffsetMs: 0, totalMs,
      timings, sizes, mimeClass: mimeClass(source.response.content.mimeType), findings
    }
  }
}

/**
 * Project a local HAR 1.2 capture into an allowlisted diagnostic report.
 * No URL, request/response text, absolute time or source digest is returned.
 * This is a bounded synchronous operation; cancellation is checked before
 * parsing and between entries, not a background-worker cancellation mechanism.
 */
export function analyzeHar(input, options = {}) {
  if (!record(options)) fail('invalid-options')
  const { slowMs = 2000, signal } = options
  if (typeof slowMs !== 'number' || !Number.isFinite(slowMs) || slowMs <= 0 ||
      slowMs > Number.MAX_SAFE_INTEGER || (signal !== undefined && !(signal instanceof AbortSignal))) fail('invalid-options')
  checkCancelled(signal)
  if (!(input instanceof Uint8Array)) fail('invalid-input')
  if (input.byteLength > MAX_INPUT_BYTES) fail('input-too-large')
  let har
  try { har = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input)) }
  catch { fail('invalid-json') }
  if (!record(har) || !record(har.log) || har.log.version !== '1.2' || !Array.isArray(har.log.entries)) fail()
  if (har.log.entries.length > MAX_ENTRIES) fail('too-many-entries')
  const projected = []
  let earliest = Infinity
  for (let index = 0; index < har.log.entries.length; index++) {
    checkCancelled(signal)
    const result = projectEntry(har.log.entries[index], index, slowMs)
    if (!result) continue
    projected.push(result)
    earliest = Math.min(earliest, result.started)
  }
  const summary = {
    totalEntries: har.log.entries.length, analyzedEntries: projected.length,
    filteredEntries: har.log.entries.length - projected.length, endpoints: 0,
    requests4xx: 0, requests5xx: 0, networkUnavailable: 0, slowRequests: 0, durationMs: 0
  }
  const endpoints = []
  const groups = new Map()
  const entries = []
  for (const { started, endpointKey, entry } of projected) {
    checkCancelled(signal)
    let endpoint = groups.get(endpointKey)
    if (!endpoint) {
      endpoint = { id: `endpoint-${String(endpoints.length + 1).padStart(3, '0')}`, method: entry.method,
        requestCount: 0, errorCount: 0, slowCount: 0, totalMs: 0, maxMs: 0 }
      groups.set(endpointKey, endpoint)
      endpoints.push(endpoint)
    }
    entry.endpointId = endpoint.id
    entry.startOffsetMs = started - earliest
    endpoint.requestCount++
    if (entry.status === 0 || entry.status >= 400) endpoint.errorCount++
    if (entry.findings.includes('slow')) { endpoint.slowCount++; summary.slowRequests++ }
    endpoint.totalMs = add(endpoint.totalMs, entry.totalMs)
    endpoint.maxMs = Math.max(endpoint.maxMs, entry.totalMs)
    if (entry.status >= 400 && entry.status < 500) summary.requests4xx++
    if (entry.status >= 500) summary.requests5xx++
    if (entry.status === 0) summary.networkUnavailable++
    summary.durationMs = Math.max(summary.durationMs, add(entry.startOffsetMs, entry.totalMs))
    entries.push(entry)
  }
  summary.endpoints = endpoints.length
  const projection = { schemaVersion: 1, settings: { slowMs }, summary, endpoints, entries }
  const reportId = `har-${createHash('sha256').update(JSON.stringify(projection)).digest('hex').slice(0, 24)}`
  return { schemaVersion: 1, reportId, settings: projection.settings, summary, endpoints, entries }
}
