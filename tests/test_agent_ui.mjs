/*
 * Contract checks for the MORVAIN-X0 and Setup screens: no HTML parsing of
 * server data, answers only go to the agent route, and the three AI settings.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const src = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');

const agent = src('../reconmind/web/static/js/views/agent.js');
const setup = src('../reconmind/web/static/js/views/setup.js');
const newscan = src('../reconmind/web/static/js/views/newscan.js');
const html = src('../reconmind/web/static/index.html');

for (const [name, code] of [['agent.js', agent], ['setup.js', setup]]) {
  for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(']) {
    assert.ok(!code.includes(bad), name + ' must not use ' + bad);
  }
}
assert.ok(agent.includes("'/agent'"), 'Plan answers go to the agent route');
assert.ok(agent.includes("'approve'") && agent.includes("'redirect'") && agent.includes("'finish'"),
  'Approve, redirect and finish are the only answers');
assert.ok(agent.includes('/static/img/morvain-x0.png'), 'Uses the approved portrait file');
assert.ok(!agent.includes('<svg') && !agent.includes('ellipse'), 'No substitute SVG face');
for (const level of ['off', 'ai', 'agent']) {
  assert.ok(html.includes('data-ai="' + level + '"'), 'AI setting ' + level + ' exists');
}
assert.ok(newscan.includes("level === 'agent' ? 'agent'"), 'Agent setting sends mode agent');
assert.ok(!setup.includes('apt install') && !setup.includes('pip install'),
  'Setup screen runs the installer, it never shows manual install commands');
console.log('Agent and Setup UI contract: all assertions passed.');
