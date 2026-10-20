import assert from 'node:assert/strict'
import { test } from 'node:test'
import { analyzeHar, HarInputError, MAX_ENTRIES, MAX_INPUT_BYTES } from '../src/analyze.js'

const bytes = value => Buffer.from(JSON.stringify(value))
const capture = entries => ({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries } })
function entry(overrides = {}) {
  return {
    startedDateTime: '2026-10-15T01:00:00.000Z', time: 100,
    request: { method: 'GET', url: 'https://example.test/items?q=1', headersSize: 120, bodySize: 0 },
    response: { status: 200, statusText: 'OK', headersSize: 180, bodySize: 250,
      content: { size: 300, mimeType: 'application/json' } },
    timings: { blocked: -1, dns: 5, connect: 20, ssl: 15, send: 5, wait: 60, receive: 10 },
    ...overrides
  }
}
function rejects(value, code = 'invalid-har', options) {
  assert.throws(() => analyzeHar(value, options), error => error instanceof HarInputError && error.code === code)
}

test('projects HAR diagnostics and computes relative offsets from the earliest supported request', () => {
  const later = entry({ startedDateTime: '2026-10-15T01:00:01.000Z' })
  const earlier = entry({ time: 3000, response: { status: 503, content: { size: 0, mimeType: 'text/plain' } },
    timings: { wait: 2500, receive: 500 } })
  const report = analyzeHar(bytes(capture([later, earlier])))
  assert.deepEqual(report.entries.map(item => item.startOffsetMs), [1000, 0])
  assert.deepEqual(report.entries[1].findings, ['http-server-error', 'slow', 'wait-dominant'])
  assert.equal(report.summary.durationMs, 3000)
  assert.equal(report.summary.requests5xx, 1)
  assert.equal(report.summary.slowRequests, 1)
  assert.equal(report.endpoints.length, 1)
  assert.deepEqual(report.endpoints[0], { id: 'endpoint-001', method: 'GET', requestCount: 2, errorCount: 1,
    slowCount: 1, totalMs: 3100, maxMs: 3000 })
  assert.equal(report.entries[1].timings.ssl, -1)
  assert.equal(report.entries[1].sizes.responseBodyBytes, -1)
  assert.match(report.reportId, /^har-[a-f0-9]{24}$/)
})

test('endpoint aliases ignore query, fragment and credentials, but distinguish origin, path and method', () => {
  const urls = ['https://user:password@example.test/items?token=secret#private', 'https://example.test/items?q=other',
    'https://example.test/other', 'https://other.test/items']
  const entries = urls.map(url => entry({ request: { method: 'GET', url } }))
  entries.push(entry({ request: { method: 'POST', url: urls[0] } }))
  const report = analyzeHar(bytes(capture(entries)))
  assert.deepEqual(report.entries.map(item => item.endpointId), ['endpoint-001', 'endpoint-001', 'endpoint-002', 'endpoint-003', 'endpoint-004'])
  assert.deepEqual(report.entries.map(item => item.method), ['GET', 'GET', 'GET', 'GET', 'POST'])
  const extensions = analyzeHar(bytes(capture(['CUSTOM-ONE', 'CUSTOM-TWO'].map(method =>
    entry({ request: { method, url: urls[0] } })))))
  assert.equal(extensions.endpoints.length, 2)
  assert.deepEqual(extensions.entries.map(item => item.method), ['OTHER', 'OTHER'])
})

test('case-sensitive method identities keep endpoint errors and timings separate', () => {
  const methods = ['PURGE', 'purge', 'PURGE', 'GET', 'get']
  const times = [100, 3000, 200, 500, 4000]
  const entries = methods.map((method, index) => entry({
    request: { method, url: `https://example.test/items?q=${index}` },
    response: { status: index === 1 || index === 4 ? 501 : 200, content: {} },
    time: times[index], timings: {}
  }))
  const report = analyzeHar(bytes(capture(entries)))
  assert.equal(report.summary.endpoints, 4)
  assert.deepEqual(report.entries.map(item => item.endpointId),
    ['endpoint-001', 'endpoint-002', 'endpoint-001', 'endpoint-003', 'endpoint-004'])
  assert.deepEqual(report.entries.map(item => item.method), ['OTHER', 'OTHER', 'OTHER', 'GET', 'OTHER'])
  assert.deepEqual(report.endpoints, [
    { id: 'endpoint-001', method: 'OTHER', requestCount: 2, errorCount: 0, slowCount: 0, totalMs: 300, maxMs: 200 },
    { id: 'endpoint-002', method: 'OTHER', requestCount: 1, errorCount: 1, slowCount: 1, totalMs: 3000, maxMs: 3000 },
    { id: 'endpoint-003', method: 'GET', requestCount: 1, errorCount: 0, slowCount: 0, totalMs: 500, maxMs: 500 },
    { id: 'endpoint-004', method: 'OTHER', requestCount: 1, errorCount: 1, slowCount: 1, totalMs: 4000, maxMs: 4000 }
  ])
  assert.ok(!JSON.stringify(report).includes('PURGE'))
  assert.ok(!JSON.stringify(report).includes('purge'))
  const renamed = structuredClone(entries)
  for (const item of renamed) {
    if (item.request.method === 'PURGE') item.request.method = 'PRIVATE-METHOD-CANARY'
    if (item.request.method === 'purge') item.request.method = 'private-method-canary'
  }
  assert.deepEqual(analyzeHar(bytes(capture(renamed))), report,
    'report identity depends on the retained grouping, not private method tokens')
})

test('only exact standard method tokens receive their controlled display names', () => {
  const methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']
  const variants = methods.flatMap(method => [method, method.toLowerCase()])
  const report = analyzeHar(bytes(capture(variants.map(method => entry({
    request: { method, url: 'https://example.test/items' }
  })))))
  assert.equal(report.endpoints.length, variants.length)
  assert.deepEqual(report.entries.map(item => item.method), methods.flatMap(method => [method, 'OTHER']))
})

test('never emits source strings, even in ignored nested, extension, prototype or MIME fields', () => {
  const canary = 'SECRET_CANARY_9a8eb37'
  const source = entry({
    request: { method: canary, url: `https://${canary}.test/${canary}?${canary}=${canary}`, headersSize: 1, bodySize: 0,
      cookies: [{ name: canary, value: canary }], headers: [{ name: canary, value: canary }],
      postData: { text: canary }, queryString: [{ name: canary, value: canary }] },
    response: { status: 0, statusText: canary, headers: [{ name: canary, value: canary }], cookies: [{ value: canary }],
      redirectURL: canary, content: { size: 3, mimeType: canary, text: canary } },
    _initiator: { url: canary }, serverIPAddress: canary, connection: canary, pageref: canary, comment: canary
  })
  const data = capture([source])
  data.log.pages = [{ title: canary, startedDateTime: source.startedDateTime, id: canary }]
  const raw = JSON.stringify(data).replace('"log":{', `"__proto__":{"polluted":"${canary}"},"log":{`)
  const report = analyzeHar(Buffer.from(raw))
  const serialized = JSON.stringify(report)
  assert.equal(serialized.includes(canary), false)
  assert.equal(serialized.includes('example.test'), false)
  assert.equal(serialized.includes(source.startedDateTime), false)
  assert.equal({}.polluted, undefined)
  assert.equal(report.entries[0].method, 'OTHER')
  assert.equal(report.entries[0].mimeClass, 'binary')
  assert.deepEqual(report.entries[0].findings, ['network-unavailable'])
})

test('report identity hashes only the allowlisted projection, not secret URLs or bodies', () => {
  const a = capture([entry()])
  const b = structuredClone(a)
  b.log.entries[0].request.url = 'https://different-secret.test/private?password=x'
  b.log.entries[0].response.content.text = 'TOP_SECRET'
  b.log.entries[0].startedDateTime = '2001-01-01T00:00:00Z'
  assert.deepEqual(analyzeHar(bytes(a)), analyzeHar(bytes(b)))
  b.log.entries[0].response.status = 404
  assert.notEqual(analyzeHar(bytes(a)).reportId, analyzeHar(bytes(b)).reportId)
})

test('filters non-HTTP URLs with no data copied into the report and retains source indexes', () => {
  const report = analyzeHar(bytes(capture([
    { request: { url: 'data:text/plain,SECRET' } }, entry(), { request: { url: 'file:///private/SECRET' } }
  ])))
  assert.equal(report.summary.filteredEntries, 2)
  assert.equal(report.summary.totalEntries, 3)
  assert.equal(report.entries[0].sourceEntryIndex, 1)
  assert.equal(JSON.stringify(report).includes('SECRET'), false)
  const empty = analyzeHar(bytes(capture([{ request: { url: 'about:blank' } }])))
  assert.equal(empty.summary.durationMs, 0)
  assert.deepEqual(empty.entries, [])
})

test('does not double-count TLS in connect or assign a network failure to CORS', () => {
  const report = analyzeHar(bytes(capture([entry(), entry({ response: { status: 0, content: {} } })])))
  assert.equal(report.entries[0].findings.includes('timing-mismatch'), false)
  assert.deepEqual(report.entries[1].findings, ['network-unavailable'])
  assert.equal(JSON.stringify(report).toLowerCase().includes('cors'), false)
  const mismatch = entry({ timings: { connect: 50, ssl: 51, wait: 100, receive: 100 } })
  assert.deepEqual(analyzeHar(bytes(capture([mismatch]))).entries[0].findings, ['timing-mismatch'])
})

test('slow threshold is inclusive and wait-dominant is an observation only on slow requests', () => {
  const source = entry({ time: 200, timings: { wait: 100 } })
  assert.deepEqual(analyzeHar(bytes(capture([source])), { slowMs: 200 }).entries[0].findings, ['slow', 'wait-dominant'])
  assert.deepEqual(analyzeHar(bytes(capture([source])), { slowMs: 201 }).entries[0].findings, [])
  const zero = entry({ time: 0, timings: {} })
  assert.deepEqual(analyzeHar(bytes(capture([zero]))).entries[0].findings, [])
})

test('uses controlled MIME and method classes, never arbitrary strings', () => {
  const cases = [['application/problem+json; charset=utf-8', 'json'], ['text/html', 'html'], ['text/css', 'css'],
    ['application/javascript', 'javascript'], ['image/png', 'image'], ['font/woff2', 'font'],
    ['audio/mp3', 'audio'], ['video/mp4', 'video'], ['application/atom+xml', 'xml'],
    ['text/plain', 'text'], ['application/octet-stream', 'binary'], ['', 'unknown']]
  for (const [mimeType, expected] of cases) {
    const source = entry({ response: { status: 200, content: { mimeType } } })
    assert.equal(analyzeHar(bytes(capture([source]))).entries[0].mimeClass, expected)
  }
  rejects(bytes(capture([entry({ request: { method: 'GET\r\nSECRET', url: 'https://a.test' } })])))
})

test('classifies Ollama NDJSON streams as JSON without retaining content or MIME parameters', () => {
  const secret = 'PRIVATE_STREAM_CONTENT_2af079';
  for (const mimeType of ['application/x-ndjson', `Application/X-NdJson; charset=utf-8; private=${secret}`]) {
    const source = entry({ response: { status: 200, content: {
      size: 150, mimeType, text: `{"response":"${secret}","done":false}\n{"done":true}\n`
    } } });
    const report = analyzeHar(bytes(capture([source])));
    assert.equal(report.entries[0].mimeClass, 'json');
    assert.ok(!JSON.stringify(report).includes(secret));
    source.response.content.text = 'different private model output';
    assert.equal(analyzeHar(bytes(capture([source]))).reportId, report.reportId);
  }
  for (const [mimeType, expected] of [['application/x-ndjson-private', 'binary'], ['text/event-stream', 'text']]) {
    const source = entry({ response: { status: 200, content: { mimeType } } });
    assert.equal(analyzeHar(bytes(capture([source]))).entries[0].mimeClass, expected);
  }
});

test('rejects malformed HAR and JSON with constant, non-reflective errors', () => {
  const invalid = [null, [], {}, { log: null }, { log: { version: '1.1', entries: [] } },
    { log: { version: '1.2', entries: {} } }, capture([null]), capture([entry({ request: {} })]),
    capture([entry({ response: {} })]), capture([entry({ timings: null })]),
    capture([entry({ request: { url: 'SECRET_INVALID_URL', method: 'GET' } })])]
  for (const value of invalid) rejects(bytes(value))
  assert.throws(() => analyzeHar(Buffer.from('{"SECRET_INVALID_JSON":')), error =>
    error.code === 'invalid-json' && !error.message.includes('SECRET'))
  rejects(Buffer.from([0xff]), 'invalid-json')
  rejects('{}', 'invalid-input')
  rejects(new ArrayBuffer(0), 'invalid-input')
  rejects(Buffer.alloc(0), 'invalid-json')
  assert.equal(analyzeHar(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes(capture([]))])).entries.length, 0)
})

test('rejects invalid numeric values without coercion; preserves unknown and fractional timing values', () => {
  for (const time of [-1, '100', null, Number.MAX_SAFE_INTEGER + 1]) rejects(bytes(capture([entry({ time })])))
  for (const value of [-2, -0.5, '0', null]) {
    rejects(bytes(capture([entry({ timings: { wait: value } })])))
    rejects(bytes(capture([entry({ request: { method: 'GET', url: 'https://a.test', bodySize: value } })])))
  }
  for (const status of [-1, 1, 99, 600, 200.5, '200', null]) rejects(bytes(capture([entry({ response: { status, content: {} } })])))
  for (const status of [0, 100, 599]) {
    assert.equal(analyzeHar(bytes(capture([entry({ response: { status, content: {} } })]))).entries[0].status, status)
  }
  rejects(bytes(capture([entry({ request: { method: 'GET', url: 'https://a.test', bodySize: 1.5 } })])))
  const report = analyzeHar(bytes(capture([entry({ time: 0.5, timings: { wait: 0.25, receive: -1 } })])))
  assert.equal(report.entries[0].timings.wait, 0.25)
  assert.equal(report.entries[0].timings.blocked, -1)
  assert.equal(report.entries[0].sizes.responseContentBytes, 300)
  rejects(Buffer.from(JSON.stringify(capture([entry()])).replace('"time":100', '"time":1e400')))
  const huge = entry({ time: Number.MAX_SAFE_INTEGER, timings: {} })
  rejects(bytes(capture([huge, huge])))
})

test('validates absolute source timestamps and emits only relative milliseconds', () => {
  for (const startedDateTime of ['SECRET', '2026-02-30T00:00:00Z', '2026-01-01',
    '2026-01-01T25:00:00Z', '2026-01-01T00:00:00+25:00', '2026-01-01T00:00:60Z']) {
    rejects(bytes(capture([entry({ startedDateTime })])))
  }
  const report = analyzeHar(bytes(capture([
    entry({ startedDateTime: '2024-02-29T08:00:00+08:00' }),
    entry({ startedDateTime: '2024-02-29T00:00:00.500Z' })
  ])))
  assert.deepEqual(report.entries.map(item => item.startOffsetMs), [0, 500])
  assert.equal(JSON.stringify(report).includes('2024'), false)
})

test('preserves fractional start offsets and duration across milliseconds and time zones', () => {
  const report = analyzeHar(bytes(capture([
    entry({ startedDateTime: '2026-10-17T08:00:00.001125+08:00', time: 0.25, timings: {} }),
    entry({ startedDateTime: '2026-10-17T00:00:00.000875Z', time: 0.125, timings: {} }),
    entry({ startedDateTime: '2026-10-17T00:00:00.000875001Z', time: 0, timings: {} })
  ])))
  assert.deepEqual(report.entries.map(item => item.startOffsetMs), [0.25, 0, 0.000001])
  assert.equal(report.summary.durationMs, 0.5)
  assert.doesNotThrow(() => JSON.stringify(report))
  assert.equal(JSON.stringify(report).includes('2026-10-17'), false)
})

test('fractional offsets remain relative before the epoch and at distant dates', () => {
  for (const [earlier, later] of [
    ['1969-12-31T23:59:59.999875Z', '1970-01-01T00:00:00.000125Z'],
    ['9999-12-31T23:59:59.999875Z', '9999-12-31T23:59:59.999999Z']
  ]) {
    const report = analyzeHar(bytes(capture([
      entry({ startedDateTime: later, time: 0, timings: {} }),
      entry({ startedDateTime: earlier, time: 0, timings: {} })
    ])))
    assert.deepEqual(report.entries.map(item => item.startOffsetMs),
      [earlier.startsWith('1969') ? 0.25 : 0.124, 0])
  }
})

test('keeps exactly representable whole-millisecond offsets across large spans', () => {
  const report = analyzeHar(bytes(capture([
    entry({ startedDateTime: '0000-01-01T00:00:00Z', time: 0, timings: {} }),
    entry({ startedDateTime: '4677-01-01T00:00:00.001Z', time: 0, timings: {} })
  ])))
  assert.equal(report.entries[1].startOffsetMs, 147591936000001)
  assert.equal(report.summary.durationMs, 147591936000001)
})

test('enforces byte and entry bounds before analysis, without truncation', () => {
  rejects(Buffer.alloc(MAX_INPUT_BYTES + 1), 'input-too-large')
  const exact = Buffer.alloc(MAX_INPUT_BYTES, ' ')
  bytes(capture([])).copy(exact)
  assert.equal(analyzeHar(exact).summary.totalEntries, 0)
  rejects(bytes(capture(Array(MAX_ENTRIES + 1).fill(null))), 'too-many-entries')
  const maximum = analyzeHar(bytes(capture(Array.from({ length: MAX_ENTRIES }, () => entry({ time: 0, timings: {} })))))
  assert.equal(maximum.entries.length, MAX_ENTRIES)
})

test('does not mutate bytes and resets endpoint aliases, counters and identity between calls', () => {
  const input = bytes(capture([entry()]))
  const before = Buffer.from(input)
  const first = analyzeHar(input)
  first.entries[0].status = 599
  assert.deepEqual(input, before)
  const second = analyzeHar(input)
  assert.equal(second.entries[0].status, 200)
  assert.equal(second.endpoints[0].id, 'endpoint-001')
  assert.equal(second.summary.totalEntries, 1)
  assert.equal(analyzeHar(bytes(capture([]))).summary.endpoints, 0)
  assert.equal(second.reportId, analyzeHar(input).reportId)
  const backing = Buffer.concat([Buffer.from('prefix'), input, Buffer.from('suffix')])
  assert.deepEqual(analyzeHar(backing.subarray(6, 6 + input.length)), second)
})

test('validates options and reports cancellation without echoing its reason', () => {
  for (const slowMs of [0, -1, Infinity, NaN, '2000', Number.MAX_SAFE_INTEGER + 1]) {
    rejects(bytes(capture([])), 'invalid-options', { slowMs })
  }
  rejects(bytes(capture([])), 'invalid-options', null)
  rejects(bytes(capture([])), 'invalid-options', { signal: { aborted: false } })
  const controller = new AbortController()
  controller.abort(new Error('SECRET_CANCEL_REASON'))
  assert.throws(() => analyzeHar(bytes(capture([])), { signal: controller.signal }), error =>
    error.code === 'cancelled' && !error.message.includes('SECRET'))
  assert.equal(analyzeHar(bytes(capture([])), { signal: new AbortController().signal }).entries.length, 0)
})
