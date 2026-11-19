/*
 * The finished app: nothing is left marked "Not built yet", the new screens
 * are routed, and none of them builds markup from text.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const html = src('../reconmind/web/static/index.html');
const app = src('../reconmind/web/static/js/app.js');
const files = ['views/hosts.js', 'views/analyst.js', 'views/report.js', 'views/targets.js', 'views/newscan.js', 'print.js']
  .map((f) => [f, src('../reconmind/web/static/js/' + f)]);

assert.ok(!html.includes('Not built yet') && !html.includes('notbuilt'), 'No Not built yet badge in the page');
for (const [name, code] of files) {
  assert.ok(!code.includes('notBuilt'), name + ' has no Not built yet button');
  for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(']) {
    assert.ok(!code.includes(bad), name + ' must not use ' + bad);
  }
}
const js = Object.fromEntries(files);
assert.ok(app.includes("parts[0] === 'hosts'") && app.includes("parts[0] === 'analyst'"), 'Host lists and Your report are routed');
assert.ok(js['views/newscan.js'].includes("kind: 'hosts'"), 'New scan starts host lists');
assert.ok(js['views/report.js'].includes("'/ask'") && js['views/report.js'].includes('printDocument('), 'Report asks and exports PDF');
assert.ok(js['views/report.js'].includes("'/api/analyst'"), 'Write your own report starts one from the scan');
assert.ok(js['views/targets.js'].includes('/api/workspace/notes'), 'Targets keeps notes');
assert.ok(js['print.js'].includes('window.print()'), 'Export PDF opens the print dialog');
assert.ok(src('../reconmind/web/static/css/app.css').includes('body.printing > *:not(#print-root)'), 'Only the document prints');

// Every part has one job.
const job = src('../reconmind/web/static/js/views/job.js');
const morvain = src('../reconmind/web/static/js/views/morvain.js');
assert.ok(!job.includes('createAgentPanel'), 'Live run does not repeat the agent conversation');
assert.ok(job.includes("href: '#/agent', text: 'Open MORVAIN-X0'"), 'Live run points agent scans to MORVAIN-X0');
assert.ok(js['views/newscan.js'].includes("body.mode === 'agent' ? '#/agent'"), 'An agent scan from New scan opens MORVAIN-X0');
assert.ok(job.includes('followList(') && job.includes("location.replace('#/job/' + next.job_id)"),
  'Live run moves on to the next host of a host list');
assert.ok(app.includes("job.status === 'running'") && app.includes('No scan is running right now'),
  'Live run opens only a running scan; otherwise it says none is running');
assert.ok(!html.includes('New folder'), 'Targets has no New folder button');
assert.ok(js['views/report.js'].includes('Write your own report'), 'Your reports are named the same everywhere');
// Malware file: shown as a future component, never starts anything.
const ns = js['views/newscan.js'];
assert.ok(html.includes('data-mode="malware"') && html.includes('Future component'), 'Malware file is shown as a future component');
assert.ok(html.includes('id="malware-file"') && /id="malware-file"[^>]*disabled/.test(html), 'Its file field is locked');
assert.ok(html.includes('Malimg'), 'It explains the planned Malimg image classifier');
assert.ok(ns.includes("if (FUTURE_MODES.has(state.mode)) return 'Malware file analysis is a future component."), 'Start stays disabled for it');
assert.ok(!ns.includes("kind: 'malware'"), 'Nothing is ever sent to the server for it');
const ui = src('../reconmind/web/static/js/ui.js');
assert.ok(ui.includes("h('table', { class: cls.table || 'md-table' }"), 'AI answers show Markdown tables as tables');
console.log('Finished app UI contract: all assertions passed.');
