/*
 * Contract checks for the MORVAIN-X0 and Setup screens: no HTML parsing of
 * server data, answers only go to the agent route, and the AI settings.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const src = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');

const agent = src('../reconmind/web/static/js/views/agent.js');
const setup = src('../reconmind/web/static/js/views/setup.js');
const newscan = src('../reconmind/web/static/js/views/newscan.js');
const html = src('../reconmind/web/static/index.html');
const morvain = src('../reconmind/web/static/js/views/morvain.js');
const app = src('../reconmind/web/static/js/app.js');

for (const [name, code] of [['agent.js', agent], ['setup.js', setup], ['morvain.js', morvain]]) {
  for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(']) {
    assert.ok(!code.includes(bad), name + ' must not use ' + bad);
  }
}
assert.ok(agent.includes("'/agent'"), 'Plan answers go to the agent route');
assert.ok(agent.includes("'approve'") && agent.includes("'redirect'") && agent.includes("'finish'"),
  'Approve, redirect and finish are the only answers');
const loops = src('../reconmind/web/static/js/morvain_loops.js');
assert.ok(agent.includes("from '../morvain_loops.js'") && loops.includes("'/static/img/morvain-x0.png'"),
  'Uses the approved portrait file');
assert.ok(!agent.includes('<svg') && !agent.includes('ellipse'), 'No substitute SVG face');
for (const level of ['off', 'ai']) {
  assert.ok(html.includes('data-ai="' + level + '"'), 'AI setting ' + level + ' exists');
}
// Agent scans start only on the MORVAIN-X0 tab; New scan points there.
assert.ok(!html.includes('data-ai="agent"') && !newscan.includes("'agent'"), 'New scan has no agent setting');
assert.ok(html.includes('<a href="#/agent">open MORVAIN-X0</a>'), 'New scan points to MORVAIN-X0 for the agent');
assert.ok(!morvain.includes('More options on New scan'), 'MORVAIN-X0 does not send you to New scan');
assert.ok(!setup.includes('apt install') && !setup.includes('pip install'),
  'Setup screen runs the installer, it never shows manual install commands');
assert.ok(html.includes('href="#/agent" data-route="agent">MORVAIN-X0</a>'), 'MORVAIN-X0 has its own tab');
assert.ok(app.includes("parts[0] === 'agent'"), 'The #/agent route exists');
assert.ok(morvain.includes("mode: 'agent'"), 'The tab starts agent scans');
const css = src('../reconmind/web/static/css/app.css');
const uiJs = src('../reconmind/web/static/js/ui.js');
const systemJs = src('../reconmind/web/static/js/views/system.js');
// One look everywhere: no Display setting; the background moves only while a scan runs.
assert.ok(!app.includes('visuals') && !systemJs.includes("section('Display'") && !css.includes('html.lite'),
  'There is no Lite, Full or Display setting');
assert.ok(uiJs.includes("classList.toggle('scanning', !!on)"), 'The Live run dot also switches the background motion');
assert.ok(css.includes('html:not(.scanning) .ring { animation: none;'), 'The radar rings move only while a scan runs');
assert.ok(css.includes('html:not(.scanning) .a1'), "The logo's signals move only while a scan runs");
console.log('Agent and Setup UI contract: all assertions passed.');
