/*
 * MORVAIN-X0, alive everywhere: three loops rendered ahead of time from the
 * approved portrait (off, working, answering), played as animated images, so
 * they move the same in every browser and window with no WebGL.
 */
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';

const path = (p) => new URL(p, import.meta.url);
const read = (p) => readFileSync(path(p), 'utf8');
const player = read('../reconmind/web/static/js/morvain_loops.js');
const agent = read('../reconmind/web/static/js/views/agent.js');
const css = read('../reconmind/web/static/css/app.css');
const renderer = read('../docs/design/morvain-rig/render_loops.py');
const IMG = '../reconmind/web/static/img/';

// The approved portrait and the maps the loops are rendered from.
assert.ok(existsSync(path(IMG + 'morvain-x0.png')), 'Approved portrait kept');
for (const name of ['morvain-off.webp', 'morvain-masks.png', 'morvain-weights.png']) {
  assert.ok(existsSync(path(IMG + 'morvain/' + name)), name + ' present');
  assert.ok(renderer.includes(name), 'The renderer uses ' + name);
}

// The three loops: real animated WebP files that repeat forever.
for (const name of ['off', 'working', 'answering']) {
  const file = path(IMG + 'morvain/loops/' + name + '.webp');
  assert.ok(existsSync(file), name + ' loop present');
  const bytes = readFileSync(file);
  assert.equal(bytes.subarray(0, 4).toString('latin1'), 'RIFF', name + ' is a WebP file');
  assert.ok(bytes.includes(Buffer.from('ANIM')) && bytes.includes(Buffer.from('ANMF')), name + ' is animated');
  const anim = bytes.indexOf(Buffer.from('ANIM'));
  assert.equal(bytes.readUInt16LE(anim + 8 + 4), 0, name + ' loops forever');
  assert.ok(statSync(file).size > 200000 && statSync(file).size < 4000000, name + ' has a sane size');
  assert.ok(existsSync(path(IMG + 'morvain/loops/' + name + '-still.webp')), name + ' still frame present');
  assert.ok(player.includes("'" + name + "'"), 'The player knows the ' + name + ' loop');
}

assert.ok(existsSync(path(IMG + 'morvain/loops/background.webp')) && player.includes("'background.webp'"),
  'The still background is its own image under the loops');
assert.ok(renderer.includes('alpha = cv2.dilate(differs, near) * 255'),
  'Each loop frame keeps only what differs from the background, so the background never shimmers');

// The renderer: one surface (weighted warp), clean background, seamless loops.
assert.match(renderer, /dx \+= \(mx - X\) \* wh/, 'Head motion is weighted per pixel (the neck eases)');
assert.match(renderer, /dy = -breath \* np\.maximum\(wb, wh \* 0\.9\)/, 'The head rides on the breath');
assert.match(renderer, /PIVOT = \(320\.0, 512\.0\)/, 'The head turns at the base of the neck');
assert.ok(renderer.includes('def clean_plate(') && renderer.includes("col = src[\"plate\"] * (1 - a) + robot * a"),
  'The robot is laid over a clean background, so the background never moves');
assert.ok(renderer.includes('% LOOP_SECONDS') && renderer.includes('% n_cycles'),
  'Steam puffs and sparks wrap round the loop, so it has no seam');
assert.match(renderer, /"working": dict\([^\n]*\n[^\n]*steam=True, sparks=False\)/, 'Working: steam, no sparks');
assert.match(renderer, /"answering": dict\([^\n]*tint=1\.0[^\n]*\n[^\n]*steam=False, sparks=True\)/, 'Answering: yellow with sparks');
assert.match(renderer, /"off": dict\(light=\(0, 0, 0\)[^\n]*\n[^\n]*steam=False, sparks=False\)/, 'Off: dark, no steam');
assert.match(renderer, /"working": dict\(light=\(1, 1, 1\)/, 'Working lights are on (red)');

// The player: every state maps to a loop; it never needs WebGL or a setting.
for (const [state, loop] of [['ready', 'off'], ['finished', 'off'], ['stopped', 'off'],
  ['thinking', 'working'], ['running', 'working'], ['awaiting', 'working'], ['done', 'working'],
  ['error', 'working'], ['answering', 'answering']]) {
  assert.match(player, new RegExp(state + ": '" + loop + "'"), state + ' plays the ' + loop + ' loop');
}
assert.ok(!/getContext|webgl|WebGL2/.test(player.replace(/no WebGL/g, '')), 'The player needs no WebGL');
assert.ok(!player.includes('prefers-reduced-motion') && !player.includes('lite'), 'No setting can stop it');
assert.ok(player.includes('requestAnimationFrame(step)') && player.includes('style.opacity'),
  'Cross fades run in JavaScript, so CSS rules cannot switch them off');
assert.ok(player.includes('Math.sin(local * 47)'), 'Powering on flickers the lights in');
assert.ok(player.includes("console.warn('MORVAIN-X0: loop ") && player.includes('PORTRAIT'),
  'A missing loop falls back to the still portrait');
assert.ok(agent.includes("import { createMorvain } from '../morvain_loops.js'"), 'The panel uses the loops');
assert.ok(agent.includes('body.setState(state);'), 'The panel passes every state, answering included');
assert.match(css, /\.mx-layer\{position:absolute;inset:0;/, 'The loops are stacked in the frame');
assert.ok(!existsSync(path('../reconmind/web/static/js/morvain_gl.js')), 'The old WebGL renderer is gone');

// Only the loops move: the frame itself never animates.
const rule = (sel) => (css.match(new RegExp(sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\{[^}]*\\}', 'g')) || []).join(' ');
for (const sel of ['.mx-stage', '.agent-corewrap']) {
  assert.ok(!/animation|transform/.test(rule(sel)), sel + ' does not move');
}
for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'eval(', 'new Function']) {
  assert.ok(!agent.includes(bad) && !player.includes(bad), 'must not use ' + bad);
}
console.log('MORVAIN-X0 loops contract: all assertions passed.');
