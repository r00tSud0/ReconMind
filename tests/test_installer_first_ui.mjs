/*
 * Regression contract: System is diagnostic; setup belongs to the installer.
 * No network access, install execution, secrets, or live scans.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const src = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');

const system = src('../reconmind/web/static/js/views/system.js');
const newscan = src('../reconmind/web/static/js/views/newscan.js');
const css = src('../reconmind/web/static/css/app.css');

assert.match(system, /t\.status === 'ready' \? 'Ready' : 'Missing'/,
  'System must retain Ready/Missing status');
assert.ok(!system.includes("t.status !== 'ready' && t.reason"),
  'No extra per-tool installation reasons');
assert.ok(!system.includes('Run Check again after installing a tool.'),
  'System summary must not direct users to manual tool installation');
assert.ok(!system.includes('t.status === \'ready\', t.install'),
  'System must not display per-tool install commands');
assert.ok(!newscan.includes('unavailableSelectedChecks'),
  'New Scan must not display per-tool availability warnings');
assert.ok(!newscan.includes('renderAvailability'),
  'New Scan must not render availability alert');
assert.ok(!css.includes('.scan-tool-warning'),
  'Removed warning styling should not remain');
assert.match(system, /Enter a new key only to replace the saved one/,
  'Saved key wording refinement must survive');
console.log('Installer-first UI contract: all assertions passed.');
