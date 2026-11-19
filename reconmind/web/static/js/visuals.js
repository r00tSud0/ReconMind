/*
 * Visual effects: full or lite.
 *
 * The full look uses frosted glass blur, drifting glows and a moving radar.
 * Without graphics acceleration (a virtual machine such as the Kali VM) the
 * browser draws all of that on the CPU and the page stutters. Lite mode
 * (class "lite" on <html>) turns those effects off; styles in app.css.
 *
 * The setting is Auto (default), Full or Lite. Auto picks lite when the
 * browser reports a software renderer, or when frames take too long.
 */

const KEY = 'reconmind.visuals';
export const CHOICES = ['auto', 'full', 'lite'];
const SOFTWARE = /llvmpipe|softpipe|swiftshader|software|vmware|virtualbox|svga|basic render/i;
const SLOW_FRAME_MS = 40;   // slower than about 25 frames a second

let reason = '';

function stored() {
  try {
    const value = window.localStorage.getItem(KEY);
    return CHOICES.includes(value) ? value : 'auto';
  } catch (err) {
    return 'auto';  // storage can be unavailable in an app window; Auto still works
  }
}

export function choice() { return stored(); }
const root = () => (typeof document !== 'undefined' && document.documentElement) || null;
export function isLite() { const r = root(); return !!r && r.classList.contains('lite'); }
export function why() { return reason; }

function apply(lite, because) {
  const r = root();
  if (r) r.classList.toggle('lite', lite);
  reason = because;
}

/* The renderer the browser reports, or '' when it does not say. */
export function rendererName() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'none';
    const info = gl.getExtension('WEBGL_debug_renderer_info');
    return String(info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
  } catch (err) {
    return '';
  }
}

function measure(frames, done) {
  if (typeof requestAnimationFrame !== 'function') return;
  const times = [];
  let last = null;
  function step(now) {
    if (last !== null) times.push(now - last);
    last = now;
    if (times.length < frames) requestAnimationFrame(step);
    else {
      times.sort((a, b) => a - b);
      done(times[Math.floor(times.length / 2)]);
    }
  }
  requestAnimationFrame(step);
}

function auto() {
  const name = rendererName();
  if (name === 'none' || SOFTWARE.test(name)) {
    apply(true, 'Lite effects are on: this computer draws the page without graphics '
      + 'acceleration' + (name && name !== 'none' ? ' (' + name.slice(0, 60) + ')' : '') + '.');
    return;
  }
  apply(false, '');
  // Give the first page a moment, then time the frames.
  setTimeout(() => measure(60, (median) => {
    if (stored() !== 'auto') return;
    if (median > SLOW_FRAME_MS) {
      apply(true, 'Lite effects are on: the page was drawing slowly (about '
        + Math.round(1000 / median) + ' frames a second).');
    }
  }), 1500);
}

export function set(value) {
  if (!CHOICES.includes(value)) return;
  try {
    window.localStorage.setItem(KEY, value);
  } catch (err) {
    // Not saved for next time, but applied now.
  }
  init(value);
}

export function init(value) {
  const pick = value || stored();
  if (pick === 'full') apply(false, 'Full effects are on because you chose Full.');
  else if (pick === 'lite') apply(true, 'Lite effects are on because you chose Lite.');
  else auto();
}
