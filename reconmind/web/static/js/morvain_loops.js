/*
 * MORVAIN-X0, alive, everywhere.
 *
 * The character plays three looping animations that were rendered ahead of
 * time from the approved portrait (docs/design/morvain-rig/render_loops.py):
 *
 *   off        lights black, breathing (ready, finished, stopped)
 *   working    red lights, steam puffing from behind it every few seconds,
 *              breathing, the head looking across the target
 *              (thinking, running, waiting for approval, done, error)
 *   answering  yellow lights, sparks bursting from behind it, breathing
 *              (while it answers your question or Tell me more)
 *
 * The background is one still image (background.webp) and each loop holds
 * only what moves over it (the robot, the steam, the sparks), so the
 * background never moves or shimmers.
 *
 * They are ordinary animated WebP images, so they play the same in every
 * browser and in the desktop window: no WebGL, no graphics card, no browser
 * setting needed, and they ignore the system's reduce motion setting.
 * Each loop repeats without a seam. The three loops sit on top of each
 * other and the visible one cross fades to the next when the state changes;
 * powering on from off flickers the red lights in. The fades are run here in
 * JavaScript (not CSS transitions), so nothing on the page can switch them off.
 *
 * If the loop files are missing, the still portrait is shown instead.
 */

const DIR = '/static/img/morvain/loops/';
const PORTRAIT = '/static/img/morvain-x0.png';
const ALT = 'MORVAIN-X0, a black chrome robotic face with red optics';
const LOOPS = ['off', 'working', 'answering'];
const STATE_LOOP = {
  ready: 'off', finished: 'off', stopped: 'off',
  thinking: 'working', running: 'working', awaiting: 'working', done: 'working', error: 'working',
  answering: 'answering',
};
const POWERED = new Set(['thinking', 'running', 'awaiting', 'answering', 'done', 'error']);
const FADE_MS = 450;
const FLICKER_MS = 750;

export function createMorvain(stage, onMissing) {
  const layers = {};
  let state = 'ready';
  let shown = 'off';
  let tween = 0;
  let dead = false;
  let failed = false;

  for (const name of LOOPS) {
    const img = document.createElement('img');
    img.className = 'mx-layer mx-layer-' + name;
    img.decoding = 'async';
    img.draggable = false;
    if (name === 'off') img.alt = ALT;
    else { img.alt = ''; img.setAttribute('aria-hidden', 'true'); }
    img.style.opacity = name === 'off' ? '1' : '0';
    img.style.visibility = name === 'off' ? 'visible' : 'hidden';
    img.addEventListener('error', () => missing(name));
    img.src = DIR + name + '.webp';
    layers[name] = img;
  }
  const background = document.createElement('img');
  background.className = 'mx-layer mx-background';
  background.alt = '';
  background.setAttribute('aria-hidden', 'true');
  background.draggable = false;
  background.addEventListener('error', () => missing('background'));
  background.src = DIR + 'background.webp';
  stage.replaceChildren(background, layers.off, layers.working, layers.answering);

  function missing(name) {
    if (failed || dead) return;
    failed = true;
    if (typeof console !== 'undefined') console.warn('MORVAIN-X0: loop ' + name + ' did not load; showing the still portrait');
    cancelAnimationFrame(tween);
    const still = document.createElement('img');
    still.className = 'mx-layer';
    still.alt = ALT;
    still.addEventListener('error', () => { if (onMissing) onMissing(); });
    still.src = PORTRAIT;
    stage.replaceChildren(still);
    api.kind = 'still';
  }

  /* Cross fade from the visible loop to `next`; from off to a powered loop,
     the new loop flickers in like lights catching. */
  function show(next) {
    if (failed || dead || next === shown) return;
    const from = layers[shown];
    const to = layers[next];
    const flicker = shown === 'off';
    shown = next;
    cancelAnimationFrame(tween);
    for (const name of LOOPS) {
      if (layers[name] !== from && layers[name] !== to) {
        layers[name].style.opacity = '0';
        layers[name].style.visibility = 'hidden';
      }
    }
    to.style.visibility = 'visible';
    // the new loop goes on top while it fades in
    stage.append(to);
    const startTo = Number(to.style.opacity) || 0;
    const length = flicker ? FLICKER_MS : FADE_MS;
    const begin = performance.now();
    const step = (now) => {
      if (dead) return;
      const p = Math.min(1, (now - begin) / length);
      let level = startTo + (1 - startTo) * (p * p * (3 - 2 * p));
      if (flicker && p < 0.8) {
        // the lights catch with a stutter before they hold
        const local = p * length / 1000;
        level *= (Math.sin(local * 47) + Math.sin(local * 31)) > 0.2 ? 1 : 0.15;
      }
      to.style.opacity = String(level);
      if (p < 1) {
        tween = requestAnimationFrame(step);
      } else {
        from.style.opacity = '0';
        from.style.visibility = 'hidden';
        api.fades += 1;
      }
    };
    tween = requestAnimationFrame(step);
  }

  const api = {
    kind: 'loops',
    fades: 0,
    puffs: 0,
    setState(next) {
      state = STATE_LOOP[next] ? next : 'ready';
      show(STATE_LOOP[state]);
    },
    state: () => state,
    loop: () => shown,
    // The working loop already puffs steam every few seconds.
    steam() {},
    destroy() {
      dead = true;
      cancelAnimationFrame(tween);
    },
  };
  stage.morvain = api;   // lets the browser tests drive and read it
  return api;
}

export { POWERED, STATE_LOOP };
