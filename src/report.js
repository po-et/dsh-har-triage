import { createHash } from 'node:crypto';

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH', 'OTHER']);
const MIMES = new Set(['json', 'html', 'css', 'javascript', 'image', 'font', 'audio', 'video', 'xml', 'text', 'binary', 'unknown']);
const FINDINGS = {
  'network-unavailable': ['No valid response', 'The capture has no valid HTTP response. It does not establish whether the request was cancelled, blocked, or disconnected.'],
  'http-client-error': ['HTTP 4xx', 'The server returned a client-error status. Inspect the original request locally; the status alone does not establish the cause.'],
  'http-server-error': ['HTTP 5xx', 'The server returned a server-error status. This is evidence of the response, not a diagnosis of the failing service.'],
  slow: ['Slow request', 'The recorded duration meets the configured threshold. Compare the measured phases before deciding what to investigate.'],
  'wait-dominant': ['Waiting dominates', 'Waiting for a response is at least half the duration of this slow request. This alone does not prove a backend or database problem.'],
  'timing-mismatch': ['Inconsistent timings', 'The recorded phase values conflict with the total or nested TLS duration. Phase proportions are hidden rather than presented as an exact breakdown.'],
};

const css = `
:root{color-scheme:light;--ink:#162635;--muted:#647382;--line:#dce4e7;--paper:#fff;--bg:#f1f5f4;--accent:#0c7165;--danger:#a33737;--amber:#a46817;font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink)}button,select{font:inherit}button,select{border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink);padding:8px 11px}button{cursor:pointer}button:hover{border-color:var(--accent);background:#f1faf7}button:disabled{opacity:.45;cursor:default}button:focus-visible,select:focus-visible{outline:3px solid #79b9ae;outline-offset:2px}a{color:var(--accent)}h1,h2,h3,p{margin:0}h1{font-size:clamp(27px,4vw,40px);line-height:1.15;letter-spacing:-1.1px}h2{font-size:18px;letter-spacing:-.3px}h3{font-size:14px}main{max-width:1440px;margin:auto;padding:32px}.eyebrow{font-size:11px;font-weight:750;letter-spacing:1.7px;color:var(--accent);margin-bottom:10px}.hero{display:flex;gap:24px;justify-content:space-between;align-items:flex-start;margin-bottom:24px}.subtitle{color:var(--muted);max-width:680px;margin-top:12px}.privacy{max-width:320px;background:#e1eeE8;border:1px solid #c4ddd2;padding:14px;border-radius:12px;font-size:12px}.privacy strong{display:block;color:#215342;margin-bottom:5px}.mono,code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.report-id{color:var(--muted);margin-top:12px;overflow-wrap:anywhere}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:20px}.metric{padding:18px 20px;border:1px solid var(--line);background:var(--paper);border-radius:12px}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;font-size:27px;letter-spacing:-.8px;margin:3px 0}.metric small{color:var(--muted)}.workspace{display:grid;grid-template-columns:280px minmax(0,1fr);gap:18px;align-items:start}.panel{background:var(--paper);border:1px solid var(--line);border-radius:13px;overflow:hidden}.panel-header{padding:17px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}.quiet{font-size:12px;color:var(--muted)}.issue-list{padding:10px;display:grid;gap:7px}.issue{display:block;text-align:left;width:100%;padding:12px;background:#f8faf9}.issue.active{border-color:var(--accent);background:#eaf5ef}.issue strong{display:block;font-size:12px}.issue small{display:block;color:var(--muted);margin-top:4px}.notice{padding:14px 18px;color:var(--muted);font-size:12px}.controls{display:flex;gap:10px;flex-wrap:wrap;padding:14px 18px;border-bottom:1px solid var(--line);align-items:center}.controls label{font-size:12px;color:var(--muted)}select{margin-left:5px;max-width:180px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;white-space:nowrap;font-size:12px}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);background:#fafcfb}th,td{padding:11px 13px;border-bottom:1px solid #eaf0ed}tbody tr{cursor:pointer}tbody tr:hover,tbody tr.selected{background:#edf7f2}tbody tr.selected td:first-child{box-shadow:inset 3px 0 var(--accent)}.request-button{padding:0;border:0;background:transparent;border-radius:0;font-family:ui-monospace,monospace;color:var(--accent);text-align:left}.status{font-weight:700}.status.bad{color:var(--danger)}.status.none{color:var(--amber)}.timing-cell{width:160px}.mini{width:140px;height:16px;display:block}.pagination{padding:12px 18px;display:flex;align-items:center;justify-content:space-between;gap:12px}.pagination button{padding:5px 10px}.detail{margin-top:18px}.detail-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.tag{padding:3px 7px;font-size:11px;font-weight:650;background:#edf4f1;border-radius:5px}.detail-body{padding:18px}.source{padding:12px;background:#f4f7f6;border-radius:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}.source p{flex:1;min-width:180px;font-size:12px}.source button{font-size:12px}.facts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0}.fact span{display:block;font-size:11px;color:var(--muted)}.fact strong{font-size:14px}.phases{width:100%;height:25px;display:block;margin:10px 0}.legend{display:flex;flex-wrap:wrap;gap:5px 16px;font-size:11px;color:var(--muted)}.legend b{color:var(--ink);font-weight:500}.findings{display:grid;gap:9px;margin-top:18px}.finding{padding:11px 13px;border-left:3px solid #c6d8cb;background:#f7faf8;font-size:12px}.finding p{color:var(--muted);margin-top:3px}.footer{margin-top:22px;color:var(--muted);font-size:11px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.empty{padding:30px 18px;color:var(--muted);text-align:center}.sr-only{position:absolute;width:1px;height:1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}#live{min-height:18px;margin-top:7px;color:var(--accent);font-size:12px}.phase-blocked{fill:#a1a9b2}.phase-dns{fill:#bea0ca}.phase-connect{fill:#80abcf}.phase-send{fill:#d7b86c}.phase-wait{fill:#469b87}.phase-receive{fill:#86bca1}.phase-unattributed{fill:#e5ece8}
@media(max-width:1050px){.workspace{grid-template-columns:220px minmax(0,1fr)}main{padding:22px}.timing-cell{display:none}.privacy{max-width:260px}}
@media(max-width:760px){main{padding:16px}.hero{display:block}.privacy{max-width:none;margin-top:18px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.workspace{display:block}.issues-panel{margin-bottom:16px}.issue-list{grid-template-columns:repeat(2,minmax(0,1fr))}.facts{grid-template-columns:repeat(2,minmax(0,1fr))}.controls{padding:12px}.metric{padding:14px}.panel-header{padding:14px}.detail-body{padding:14px}}
@media(prefers-reduced-motion:no-preference){button{transition:background .12s,border-color .12s}}
`;

function invalid() { throw new TypeError('Invalid anonymous diagnostic report.'); }
function number(value, integer = false) {
  if (!Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER || value < -1 || (integer && !Number.isInteger(value))) invalid();
  return value;
}
function pickNumbers(value, names, integer = false) {
  if (!value || typeof value !== 'object') invalid();
  return Object.fromEntries(names.map((name) => [name, number(value[name], integer)]));
}
function project(report) {
  if (report?.schemaVersion !== 1 || typeof report.reportId !== 'string' || !/^har-[a-f0-9]{24}$/.test(report.reportId) || !Array.isArray(report.entries) || report.entries.length > 10000 || !Array.isArray(report.endpoints) || report.endpoints.length > 10000) invalid();
  const endpointId = (id) => { if (typeof id !== 'string' || !/^endpoint-\d{3,5}$/.test(id)) invalid(); return id; };
  const method = (value) => METHODS.has(value) ? value : 'OTHER';
  const seen = new Set();
  return {
    schemaVersion: 1, reportId: report.reportId,
    settings: pickNumbers(report.settings, ['slowMs']),
    summary: pickNumbers(report.summary, ['totalEntries', 'analyzedEntries', 'filteredEntries', 'endpoints', 'requests4xx', 'requests5xx', 'networkUnavailable', 'slowRequests', 'durationMs']),
    endpoints: report.endpoints.map((entry) => ({ id: endpointId(entry.id), method: method(entry.method), ...pickNumbers(entry, ['requestCount', 'errorCount', 'slowCount', 'totalMs', 'maxMs']) })),
    entries: report.entries.map((entry) => {
      const index = number(entry.sourceEntryIndex, true);
      if (index < 0 || seen.has(index) || !Number.isInteger(entry.status) || (entry.status !== 0 && entry.status < 100) || entry.status > 599 || !Array.isArray(entry.findings)) invalid();
      seen.add(index);
      return {
        sourceEntryIndex: index, endpointId: endpointId(entry.endpointId), method: method(entry.method), status: entry.status,
        startOffsetMs: number(entry.startOffsetMs), totalMs: number(entry.totalMs),
        timings: pickNumbers(entry.timings, ['blocked', 'dns', 'connect', 'ssl', 'send', 'wait', 'receive']),
        sizes: pickNumbers(entry.sizes, ['requestBodyBytes', 'responseBodyBytes', 'responseContentBytes', 'requestHeadersBytes', 'responseHeadersBytes'], true),
        mimeClass: MIMES.has(entry.mimeClass) ? entry.mimeClass : 'unknown',
        findings: [...new Set(entry.findings.filter((code) => typeof code === 'string' && Object.hasOwn(FINDINGS, code)))],
      };
    }),
  };
}

const script = `
'use strict';
const report=JSON.parse(document.getElementById('report-data').textContent);
const findingText=${JSON.stringify(FINDINGS)};
const phaseNames=['blocked','dns','connect','send','wait','receive'];
const phaseLabels={blocked:'Blocked',dns:'DNS',connect:'Connection (includes TLS)',send:'Send',wait:'Wait / TTFB',receive:'Receive'};
const byIndex=new Map(report.entries.map(e=>[e.sourceEntryIndex,e]));
let selected=report.entries.find(e=>e.findings.length)?.sourceEntryIndex??report.entries[0]?.sourceEntryIndex;
let page=0;const pageSize=40;
const $=id=>document.getElementById(id);
function el(tag,text,className){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;}
function duration(n){return n<0?'Unknown':n>=1000?(n/1000).toFixed(2)+' s':n.toFixed(1)+' ms';}
function bytes(n){return n<0?'Unknown':n>=1048576?(n/1048576).toFixed(2)+' MiB':n>=1024?(n/1024).toFixed(1)+' KiB':n+' B';}
function svg(width,height,label){const node=document.createElementNS('http://www.w3.org/2000/svg','svg');node.setAttribute('viewBox','0 0 '+width+' '+height);node.setAttribute('role','img');node.setAttribute('aria-label',label);return node;}
function rect(node,x,width,className,height=16){if(width<=0)return;const r=document.createElementNS(node.namespaceURI,'rect');r.setAttribute('x',x);r.setAttribute('y','0');r.setAttribute('width',width);r.setAttribute('height',height);r.setAttribute('class',className);node.append(r);}
function filtered(){const filter=$('status-filter').value;const endpoint=$('endpoint-filter').value;return report.entries.filter(e=>(endpoint==='all'||e.endpointId===endpoint)&&(filter==='all'||filter==='failed'&&(e.status===0||e.status>=400)||filter==='4xx'&&e.status>=400&&e.status<500||filter==='5xx'&&e.status>=500||filter==='network'&&e.status===0||filter==='slow'&&e.findings.includes('slow')||filter==='issues'&&e.findings.length>0));}
function choose(index){selected=index;const position=filtered().findIndex(e=>e.sourceEntryIndex===index);if(position>=0)page=Math.floor(position/pageSize);renderTable();renderDetail();document.querySelectorAll('.issue').forEach(b=>b.classList.toggle('active',Number(b.dataset.index)===index));}
function renderTable(){const rows=filtered();const pages=Math.max(1,Math.ceil(rows.length/pageSize));page=Math.min(page,pages-1);$('request-rows').replaceChildren();
for(const e of rows.slice(page*pageSize,(page+1)*pageSize)){const tr=el('tr');if(e.sourceEntryIndex===selected)tr.className='selected';tr.addEventListener('click',()=>choose(e.sourceEntryIndex));
const label=el('button','#'+(e.sourceEntryIndex+1),'request-button');label.type='button';label.setAttribute('aria-label','Inspect source entry '+e.sourceEntryIndex);label.addEventListener('click',event=>{event.stopPropagation();choose(e.sourceEntryIndex);});const first=el('td');first.append(label);tr.append(first,el('td',e.endpointId,'mono'),el('td',e.method),el('td',e.status===0?'No response':e.status,'status '+(e.status>=400?'bad':e.status===0?'none':'')),el('td',duration(e.totalMs)));
const timeline=el('td',undefined,'timing-cell');const chart=svg(140,16,'Relative request timing');chart.classList.add('mini');rect(chart,0,140,'phase-unattributed');if(report.summary.durationMs>0&&e.startOffsetMs>=0&&e.totalMs>=0)rect(chart,Math.min(140,e.startOffsetMs/report.summary.durationMs*140),Math.min(140-e.startOffsetMs/report.summary.durationMs*140,e.totalMs/report.summary.durationMs*140),'phase-wait');timeline.append(chart);tr.append(timeline,el('td',e.findings.length?e.findings.length+(e.findings.length===1?' signal':' signals'):'—'));$('request-rows').append(tr);}
$('empty-table').hidden=rows.length!==0;$('page-label').textContent=rows.length?((page*pageSize+1)+'–'+Math.min(rows.length,(page+1)*pageSize)+' of '+rows.length+' matching requests'):'No matching requests';$('previous').disabled=page===0;$('next').disabled=page>=pages-1;
}
function fact(label,value){const node=el('div',undefined,'fact');node.append(el('span',label),el('strong',value));return node;}
function renderDetail(){const e=byIndex.get(selected);$('detail-body').replaceChildren();if(!e){$('detail-title').textContent='No request selected';$('detail-body').append(el('p','No analyzable requests were included.','quiet'));return;}
$('detail-title').textContent='Request #'+(e.sourceEntryIndex+1);$('detail-endpoint').textContent=e.endpointId;
const source=el('div',undefined,'source');const copy=el('button','Copy source locator');copy.type='button';copy.addEventListener('click',async()=>{try{await navigator.clipboard.writeText('log.entries['+e.sourceEntryIndex+']');$('live').textContent='Copied source locator.';}catch{$('live').textContent='Source locator: log.entries['+e.sourceEntryIndex+']';}});source.append(el('p','Find this request in your original HAR: '),el('code','log.entries['+e.sourceEntryIndex+']'),copy);
const facts=el('div',undefined,'facts');facts.append(fact('HTTP status',e.status===0?'No valid response':e.status),fact('Total duration',duration(e.totalMs)),fact('Relative start',duration(e.startOffsetMs)),fact('Content class',e.mimeClass),fact('Response body (wire)',bytes(e.sizes.responseBodyBytes)),fact('Response content',bytes(e.sizes.responseContentBytes)),fact('Request body',bytes(e.sizes.requestBodyBytes)),fact('TLS within connection',duration(e.timings.ssl)));
const phases=el('div');phases.append(el('h3','Recorded timing phases'));const sum=phaseNames.reduce((n,key)=>n+Math.max(0,e.timings[key]),0);const mismatch=e.findings.includes('timing-mismatch')||e.totalMs>=0&&sum>e.totalMs+Math.max(1,e.totalMs*.01);
if(e.totalMs>0&&!mismatch){const chart=svg(1000,25,'Recorded phase durations, with TLS included in connection time');chart.classList.add('phases');rect(chart,0,1000,'phase-unattributed',25);let x=0;for(const key of phaseNames){const width=Math.min(1000-x,Math.max(0,e.timings[key])/e.totalMs*1000);rect(chart,x,width,'phase-'+key,25);x+=width;}phases.append(chart);}else phases.append(el('p',mismatch?'Recorded phase timing is inconsistent; proportions hidden.':'No usable total duration; proportions unavailable.','notice'));
const legend=el('div',undefined,'legend');for(const key of phaseNames){const item=el('span',phaseLabels[key]+': ');item.append(el('b',duration(e.timings[key])));legend.append(item);}phases.append(legend,el('p','TLS is part of connection time, never added twice. Grey space is unattributed time; unknown phases are not treated as zero.','notice'));
const findings=el('div',undefined,'findings');for(const code of e.findings){const item=el('div',undefined,'finding');item.append(el('h3',findingText[code][0]),el('p',findingText[code][1]));findings.append(item);}if(!e.findings.length)findings.append(el('p','No configured diagnostic signals for this request. This does not certify that the request is correct.','quiet'));$('detail-body').append(source,facts,phases,findings);
}
function renderIssues(){const entries=report.entries.filter(e=>e.findings.length);$('issue-count').textContent=entries.length+' requests';const ordered=[...entries].sort((a,b)=>Number(b.status===0||b.status>=400)-Number(a.status===0||a.status>=400)||b.totalMs-a.totalMs||a.sourceEntryIndex-b.sourceEntryIndex);for(const e of ordered.slice(0,12)){const b=el('button',undefined,'issue');b.type='button';b.dataset.index=String(e.sourceEntryIndex);b.append(el('strong','#'+(e.sourceEntryIndex+1)+' · '+e.endpointId),el('small',e.findings.map(code=>findingText[code][0]).join(' · ')));b.addEventListener('click',()=>{$('status-filter').value='all';$('endpoint-filter').value='all';choose(e.sourceEntryIndex);$('detail').scrollIntoView({block:'nearest'});});$('issue-list').append(b);}if(!entries.length)$('issue-list').append(el('p','No configured diagnostic signals.','notice'));$('issue-note').textContent=entries.length>12?'Showing 12 prioritized requests. Choose “With signals” to inspect all.':'Signals describe observed data, not established root causes.';}
for(const e of report.endpoints){const option=el('option',e.id);option.value=e.id;$('endpoint-filter').append(option);}
$('status-filter').addEventListener('change',()=>{page=0;renderTable();});$('endpoint-filter').addEventListener('change',()=>{page=0;renderTable();});$('previous').addEventListener('click',()=>{page--;renderTable();});$('next').addEventListener('click',()=>{page++;renderTable();});renderIssues();choose(selected);
`;

function escapeHtml(value) { return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }
function inlineJson(value) { return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`); }
function hash(value) { return createHash('sha256').update(value).digest('base64'); }
function displayDuration(value) { return value < 0 ? 'Unknown' : value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${value.toFixed(1)} ms`; }

/** Render only the numeric, allowlisted diagnostic projection, never raw HAR. */
export function renderReport(input) {
  const report = project(input);
  const s = report.summary;
  const failed = s.requests4xx + s.requests5xx + s.networkUnavailable;
  const signals = report.entries.filter((entry) => entry.findings.length).length;
  const metric = (label, value, detail) => `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></div>`;
  const csp = `default-src 'none'; script-src 'sha256-${hash(script)}'; style-src 'sha256-${hash(css)}'; img-src 'none'; connect-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${escapeHtml(csp)}"><title>HAR Triage — offline network diagnostics</title><style>${css}</style></head>
<body><main><header class="hero"><div><p class="eyebrow">HAR TRIAGE / OFFLINE REPORT</p><h1>Find the request.<br>Keep the traffic private.</h1><p class="subtitle"><span lang="zh">网络诊断 · </span>Inspect failures and slow phases without sharing raw browser traffic. Follow each signal back to its original HAR entry.</p><p class="report-id mono">${escapeHtml(report.reportId)}</p></div><aside class="privacy"><strong>Anonymous diagnostic projection</strong>No URLs, hostnames, paths, query values, headers, bodies, absolute timestamps, or raw error text are included. Numeric timings and sizes remain. This is not a sanitized copy of your HAR.</aside></header>
<section class="metrics" aria-label="Diagnostic summary">${metric('Requests analyzed', s.analyzedEntries, `${s.totalEntries} source entries · ${s.filteredEntries} filtered`)}${metric('Error responses / unavailable', failed, `${s.requests4xx} client · ${s.requests5xx} server · ${s.networkUnavailable} unavailable`)}${metric('Slow requests', s.slowRequests, `Threshold: ${displayDuration(report.settings.slowMs)}`)}${metric('Capture span', displayDuration(s.durationMs), `${s.endpoints} anonymous endpoints · ${signals} requests with signals`)}</section>
<div class="workspace"><aside class="panel issues-panel"><div class="panel-header"><h2>Investigate</h2><span id="issue-count" class="quiet"></span></div><div id="issue-list" class="issue-list"></div><p id="issue-note" class="notice"></p></aside><div>
<section class="panel"><div class="panel-header"><h2>Request evidence</h2><span class="quiet">Original source order</span></div><div class="controls"><label>Status<select id="status-filter"><option value="all">All requests</option><option value="failed">Errors / unavailable</option><option value="4xx">HTTP 4xx</option><option value="5xx">HTTP 5xx</option><option value="network">No valid response</option><option value="slow">Slow requests</option><option value="issues">With signals</option></select></label><label>Endpoint<select id="endpoint-filter"><option value="all">All endpoints</option></select></label></div><div class="table-wrap"><table><caption class="sr-only">Anonymous requests; select a request to inspect its source index and recorded phases.</caption><thead><tr><th>Source #</th><th>Endpoint</th><th>Method</th><th>Status</th><th>Duration</th><th class="timing-cell">Relative timeline</th><th>Signals</th></tr></thead><tbody id="request-rows"></tbody></table></div><p id="empty-table" class="empty" hidden>No requests match these filters.</p><div class="pagination"><span id="page-label" class="quiet"></span><div><button id="previous" type="button">Previous</button> <button id="next" type="button">Next</button></div></div></section>
<section id="detail" class="panel detail" aria-label="Selected request details"><div class="panel-header"><div class="detail-head"><h2 id="detail-title">Request details</h2><span id="detail-endpoint" class="tag mono"></span></div><span class="quiet">Read-only evidence</span></div><div id="detail-body" class="detail-body"></div></section><p id="live" role="status" aria-live="polite"></p></div></div>
<footer class="footer"><span>Source indices are zero-based: request #43 is log.entries[42].</span><span>No recording, request editing, network replay, or root-cause guarantees.</span></footer><noscript><p class="notice">JavaScript is required to filter the anonymous request evidence. This report makes no network requests.</p></noscript></main>
<script id="report-data" type="application/json">${inlineJson(report)}</script><script>${script}</script></body></html>`;
}
