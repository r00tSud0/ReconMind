/*
 * MORVAIN-X0, alive: one surface that bends (a WebGL mesh warp of the approved
 * portrait), so the head, neck and chest move together. Its lights are off
 * until the agent works, steam plays once and fades, the background stays.
 */
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';

const path = (p) => new URL(p, import.meta.url);
const read = (p) => readFileSync(path(p), 'utf8');
const gl = read('../reconmind/web/static/js/morvain_gl.js');
const agent = read('../reconmind/web/static/js/views/agent.js');
const css = read('../reconmind/web/static/css/app.css');
const html = read('../reconmind/web/static/index.html');
const IMG = '../reconmind/web/static/img/';

// The approved portrait is the picture that moves; the maps are made from it.
assert.ok(existsSync(path(IMG + 'morvain-x0.png')), 'Approved portrait kept');
assert.ok(gl.includes("IMG + 'morvain-x0.png'"), 'The portrait itself is drawn');
const maps = { 'morvain-off.webp': 'RIFF', 'morvain-masks.png': '\x89PNG', 'morvain-weights.png': '\x89PNG' };
for (const [name, magic] of Object.entries(maps)) {
  const file = IMG + 'morvain/' + name;
  assert.ok(existsSync(path(file)) && statSync(path(file)).size > 1000, name + ' present');
  assert.equal(readFileSync(path(file)).subarray(0, 4).toString('latin1'), magic, name + ' has the right format');
  assert.ok(gl.includes("'morvain/" + name + "'"), name + ' used');
}
for (const old of ['bg', 'body-off', 'head-off', 'body-lit', 'head-lit', 'eyes-lit']) {
  assert.ok(!existsSync(path(IMG + 'morvain/morvain-' + old + '.webp')), 'Old cut out layer ' + old + ' removed');
}
assert.ok(agent.includes("import { createMorvain } from '../morvain_gl.js'"), 'The panel uses the warp');

// One surface: the head, neck and breath move pixels by weight maps, never as separate pieces.
assert.match(gl, /d \+= \(moved - p\) \* wh;/, 'Head motion is weighted per pixel (the neck eases)');
assert.match(gl, /uBreath \* max\(wb, wh \* 0\.9\)/, 'The head rides on the breath');
assert.match(gl, /const PIVOT = \[320, 512\];/, 'The head turns at the base of the neck');
assert.ok(gl.includes('spring('), 'Motion is spring eased, not keyframed');
assert.ok(!/\.mx-(head|body)\b/.test(css), 'No separately moving head or body layers');

// Only the robot moves: the frame never animates.
const rule = (sel) => (css.match(new RegExp(sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\{[^}]*\\}', 'g')) || []).join(' ');
for (const sel of ['.mx-stage', '.agent-corewrap']) {
  assert.ok(!/animation|transform/.test(rule(sel)), sel + ' does not move');
}
assert.ok(!html.includes('morvain-motion.css'), 'The earlier whole-picture motion sheet is not loaded');

// Lights: off until powered, on while the agent works.
assert.match(gl, /ready: +\{ light: \[0, 0, 0\]/, 'Ready (no scan) is powered down');
assert.ok(!/POWERED = new Set\(\[[^\]]*'ready'/.test(gl + agent), 'Ready never counts as powered');
for (const st of ['thinking', 'running', 'awaiting', 'done', 'error']) {
  assert.match(gl, new RegExp(st + ': +\\{ light: \\[1'), st + ' lights the eyes');
}
assert.match(css, /\.powered \.mx-still-off\{opacity:0;/, 'Fallback: lights still come on without WebGL');

// Steam: each puff fades to nothing; while working it vents every few seconds; never when off.
assert.match(gl, /const STEAM_SECONDS = [\d.]+;/, 'Each puff has a fixed length');
assert.match(gl, /const PUFF_GAP = \[[\d.]+, [\d.]+\];/, 'Puffs repeat after a short gap');
assert.match(gl, /if \(POWERED\.has\(state\) && steamStart < 0 && nextPuff && t >= nextPuff\) \{ steamStart = t;/,
  'It vents again only while powered');
assert.match(gl, /if \(!POWERED\.has\(state\)\) nextPuff = 0;/, 'Powered down: no more steam');
assert.match(gl, /1\.0 - smoothstep\(0\.42, 1\.0, uSteam\)/, 'Steam fades out');
assert.ok(agent.includes('body.steam()'), 'Steam is triggered by state changes');

// Accessibility, speed and safety.
assert.ok(gl.includes("prefers-reduced-motion: reduce"), 'Reduced motion is honoured');
assert.match(gl, /const breath = calm \? 0/, 'No breathing with reduced motion');
assert.match(gl, /steamStart >= 0 && !calm/, 'No steam with reduced motion');
assert.match(gl, /lite\(\) && now - lastDraw < 32/, 'Lite draws about 30 frames a second');
assert.ok(gl.includes('webglcontextlost') && gl.includes('stillFallback'), 'Falls back to a still portrait');
for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'eval(', 'new Function']) {
  assert.ok(!agent.includes(bad) && !gl.includes(bad), 'must not use ' + bad);
}
console.log('MORVAIN-X0 warp contract: all assertions passed.');
