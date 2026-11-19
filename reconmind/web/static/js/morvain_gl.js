/*
 * MORVAIN-X0, alive.
 *
 * The approved portrait (img/morvain-x0.png) is drawn as one surface that
 * bends: a mesh warp in a WebGL fragment shader. Maps made from the same
 * portrait (img/morvain/, see its README) say how much each pixel follows the
 * head (full on the head, easing down the neck, none on the shoulders) and
 * the breath (chest and shoulders). Because it is one surface, nothing can
 * come apart at the neck or chest, and the background only ever bends by a
 * pixel or two right next to the robot.
 *
 * Motion comes from springs that chase targets set by the agent's state, plus
 * slow organic noise, so it eases, overshoots a little and settles. The red
 * lights are mixed between the portrait and its powered down version, per
 * group (eyes, head, body), so they come on with a flicker and fade out.
 * Steam is drawn behind the robot. Each puff rises and fades away; while
 * the agent works it vents again every few seconds, and when it is powered
 * down there is none.
 *
 * Without WebGL, a still fallback swaps the powered down and lit portraits.
 * With reduced motion requested, nothing moves and there is no steam; the
 * lights still switch on and off. Lite mode (chosen on its own for virtual
 * machines and software renderers, or picked on System, Display) uses the
 * still fallback too: a virtual machine's graphics driver can freeze the
 * whole screen under constant WebGL drawing.
 */

const IMG = '/static/img/';
const SOURCES = {
  lit: IMG + 'morvain-x0.png',
  off: IMG + 'morvain/morvain-off.webp',
  mask: IMG + 'morvain/morvain-masks.png',
  weight: IMG + 'morvain/morvain-weights.png',
};
const SIZE = [640, 800];
const PIVOT = [320, 512];          // the base of the neck, in portrait pixels
const STEAM_SECONDS = 3.2;
// While powered, a new puff starts this many seconds after the last one ends.
const PUFF_GAP = [1.2, 3.2];
const ALT = 'MORVAIN-X0, a black chrome robotic face with red optics';

const VERT = `
attribute vec2 aPos;
varying vec2 vUv;
void main() {
  vUv = vec2(aPos.x * 0.5 + 0.5, 0.5 - aPos.y * 0.5);
  gl_Position = vec4(aPos, 0.0, 1.0);
}`;

const FRAG = `
precision mediump float;
varying vec2 vUv;
uniform sampler2D uLit, uOff, uMask, uWeight;
uniform vec2 uSize, uPivot, uShift;
uniform float uRot, uNod, uBreath, uGlow, uSteam, uTime;
uniform vec3 uLight;

float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), f.x),
             mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), f.x), f.y);
}
float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 4; i++) { v += a * noise(p); p *= 2.03; a *= 0.5; }
  return v;
}

void main() {
  vec2 p = vUv * uSize;
  vec4 w = texture2D(uWeight, vUv);
  float wh = w.r, wb = w.g;

  // Breath: the chest and shoulders rise and widen a hair; the head rides on them.
  vec2 d = vec2((p.x - uSize.x * 0.5) * 0.0035 * uBreath * wb,
                -1.7 * uBreath * max(wb, wh * 0.9));
  // Head: a roll about the neck, a small nod and a shift, eased by the head map.
  vec2 q = p - uPivot;
  float c = cos(uRot), s = sin(uRot);
  vec2 moved = vec2(c * q.x - s * q.y, s * q.x + c * q.y);
  moved.y *= 1.0 + uNod;
  moved += uPivot + uShift;
  d += (moved - p) * wh;

  vec2 uv = clamp((p - d) / uSize, vec2(0.0), vec2(1.0));
  vec3 lit = texture2D(uLit, uv).rgb;
  vec3 off = texture2D(uOff, uv).rgb;
  vec4 m = texture2D(uMask, uv);
  float k = clamp(m.r * uLight.x + m.g * uLight.y + m.b * uLight.z, 0.0, 1.0);
  vec3 col = mix(off, lit, k);
  col += (lit - off) * k * uGlow;

  if (uSteam >= 0.0 && uSteam < 1.0) {
    float dens = 0.0;
    for (int i = 0; i < 2; i++) {
      float side = i == 0 ? -1.0 : 1.0;
      vec2 vent = vec2(uSize.x * (0.5 + side * 0.34), uSize.y * 0.60);
      vec2 r = vec2((p.x - vent.x) / uSize.x, (vent.y - p.y) / uSize.x);
      float height = 0.06 + 0.62 * uSteam;
      float width = 0.025 + 0.22 * max(r.y, 0.0) + 0.04 * uSteam;
      float shape = exp(-(r.x * r.x) / (2.0 * width * width))
                  * smoothstep(-0.02, 0.04, r.y) * (1.0 - smoothstep(height * 0.55, height, r.y));
      float n = fbm(vec2(r.x * 8.0 + side * 3.7, r.y * 5.0 - uTime * 1.3));
      dens += shape * smoothstep(0.28, 0.75, n);
    }
    float env = smoothstep(0.0, 0.12, uSteam) * (1.0 - smoothstep(0.42, 1.0, uSteam));
    float behind = 1.0 - 0.75 * m.a;   // mostly behind the robot, a thin veil in front
    vec3 vapour = vec3(0.74, 0.74, 0.79) + vec3(0.18, 0.0, 0.01) * uLight.y;
    col = mix(col, vapour, clamp(dens * env * behind * 0.85, 0.0, 0.7));
  }
  gl_FragColor = vec4(col, 1.0);
}`;

/* What each agent state asks of the body. light: eyes, head lights, body lights. */
const POSES = {
  ready:    { light: [0, 0, 0],      glow: 0,    breath: [0.55, 5.6], head: 'rest' },
  thinking: { light: [1, 0.85, 0.7], glow: 0.1,  breath: [0.8, 4.4],  head: 'think' },
  running:  { light: [1, 1, 1],      glow: 0.22, breath: [1.0, 3.4],  head: 'scan' },
  awaiting: { light: [1, 1, 0.9],    glow: 0.14, breath: [0.7, 5.0],  head: 'attend' },
  done:     { light: [1, 0.8, 0.75], glow: 0.08, breath: [0.6, 5.2], head: 'rest' },
  error:    { light: [1, 1, 1],      glow: 0.18, breath: [0.9, 3.8],  head: 'twitch' },
  finished: { light: [0, 0, 0],      glow: 0,    breath: [0.5, 6.0],  head: 'rest' },
  stopped:  { light: [0, 0, 0],      glow: 0,    breath: [0.5, 6.0],  head: 'rest' },
};
const POWERED = new Set(['thinking', 'running', 'awaiting', 'done', 'error']);

// Smooth noise in time: a few sines at unrelated speeds never quite repeat.
const wobble = (t, seed) => (Math.sin(t * 0.73 + seed) * 0.5 + Math.sin(t * 1.31 + seed * 2.1) * 0.3
  + Math.sin(t * 2.17 + seed * 3.7) * 0.2);

function loadImage(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.decoding = 'async';
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('could not load ' + src));
    img.src = src;
  });
}

function reducedMotion() {
  try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (err) { return false; }
}
function lite() {
  return typeof document !== 'undefined' && document.documentElement.classList.contains('lite');
}

/* A spring that chases a target: it eases in, overshoots a touch and settles. */
function spring(stiffness, damping) {
  return { x: 0, v: 0, step(target, dt) {
    const a = stiffness * (target - this.x) - damping * this.v;
    this.v += a * dt;
    this.x += this.v * dt;
    return this.x;
  } };
}

function stillFallback(stage, onMissing) {
  // No WebGL: the lit portrait under the powered down one; the lights fade in and out.
  const lit = document.createElement('img');
  lit.className = 'mx-still';
  lit.src = SOURCES.lit;
  lit.alt = ALT;
  lit.addEventListener('error', () => { if (onMissing) onMissing(); });
  const off = document.createElement('img');
  off.className = 'mx-still mx-still-off';
  off.src = SOURCES.off;
  off.alt = '';
  off.setAttribute('aria-hidden', 'true');
  off.addEventListener('error', () => off.remove());
  stage.replaceChildren(lit, off);
  stage.classList.add('mx-fallback');
  return {
    kind: 'still',
    setState(state) { stage.classList.toggle('powered', POWERED.has(state)); },
    steam() {},
    destroy() {},
  };
}

export function createMorvain(stage, onMissing) {
  if (lite()) return stillFallback(stage, onMissing);
  const canvas = document.createElement('canvas');
  canvas.className = 'mx-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  let gl = null;
  try {
    gl = canvas.getContext('webgl', { antialias: false, alpha: false, premultipliedAlpha: false,
      powerPreference: 'low-power' }) || canvas.getContext('experimental-webgl');
  } catch (err) {
    gl = null;
  }
  if (!gl) return stillFallback(stage, onMissing);

  // Until the images arrive, the still portrait shows in place.
  const still = document.createElement('img');
  still.className = 'mx-still';
  still.src = SOURCES.off;
  still.alt = ALT;
  stage.replaceChildren(still, canvas);

  let program = null;
  let uniforms = {};
  let ready = false;
  let dead = false;
  let frame = 0;
  let lastDraw = 0;
  let state = 'ready';
  let steamStart = -1;
  let nextPuff = 0;
  let powerStart = -1;
  let shown = false;
  const lightNow = [0, 0, 0];
  let glowNow = 0;
  let breathPhase = 0;
  let breathAmp = 0.55;
  let breathPeriod = 5.6;
  const head = { rot: spring(16, 6.5), x: spring(14, 6), y: spring(14, 6), nod: spring(12, 6) };
  let nextTwitch = 0;
  let api = null;

  function compile(type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      throw new Error(gl.getShaderInfoLog(shader) || 'shader did not compile');
    }
    return shader;
  }

  function texture(unit, img) {
    const tex = gl.createTexture();
    gl.activeTexture(gl.TEXTURE0 + unit);
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false);
    gl.pixelStorei(gl.UNPACK_COLORSPACE_CONVERSION_WEBGL, gl.NONE);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, img);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  }

  function fail() {
    if (dead) return;
    dead = true;
    cancelAnimationFrame(frame);
    const fallback = stillFallback(stage, onMissing);
    fallback.setState(state);
    api.kind = 'still';
    api.setState = fallback.setState;
  }

  function setup(images) {
    program = gl.createProgram();
    gl.attachShader(program, compile(gl.VERTEX_SHADER, VERT));
    gl.attachShader(program, compile(gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error('shader did not link');
    gl.useProgram(program);
    const quad = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, quad);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const pos = gl.getAttribLocation(program, 'aPos');
    gl.enableVertexAttribArray(pos);
    gl.vertexAttribPointer(pos, 2, gl.FLOAT, false, 0, 0);
    for (const name of ['uLit', 'uOff', 'uMask', 'uWeight', 'uSize', 'uPivot', 'uShift', 'uRot',
      'uNod', 'uBreath', 'uGlow', 'uSteam', 'uTime', 'uLight']) {
      uniforms[name] = gl.getUniformLocation(program, name);
    }
    ['lit', 'off', 'mask', 'weight'].forEach((key, i) => {
      texture(i, images[key]);
      gl.uniform1i(uniforms['u' + key.charAt(0).toUpperCase() + key.slice(1)], i);
    });
    gl.uniform2f(uniforms.uSize, SIZE[0], SIZE[1]);
    gl.uniform2f(uniforms.uPivot, PIVOT[0], PIVOT[1]);
    ready = true;
    still.remove();
    frame = requestAnimationFrame(tick);
  }

  function headTarget(t, mode) {
    switch (mode) {
      case 'think':   // tips the head as it weighs things up
        return { rot: -0.026 + 0.006 * wobble(t * 0.5, 1), x: -2.2 + 0.8 * wobble(t * 0.4, 2),
          y: 1.2, nod: 0.004 };
      case 'scan': {  // looks across the target, easing at each end
        const s = Math.sin((t / 4.8) * Math.PI * 2);
        return { rot: 0.02 * s + 0.004 * wobble(t, 3), x: 4.2 * s, y: -0.6 + 0.5 * Math.abs(s),
          nod: -0.004 * Math.abs(s) };
      }
      case 'attend':  // faces you, lifted slightly
        return { rot: 0.003 * wobble(t * 0.3, 4), x: 0.5 * wobble(t * 0.25, 5), y: -2.4, nod: -0.006 };
      case 'twitch':
        return { rot: 0.004 * wobble(t * 0.4, 6), x: 0, y: 0, nod: 0 };
      default:        // at rest: only the slightest drift
        return { rot: 0.005 * wobble(t * 0.22, 7), x: 0.9 * wobble(t * 0.18, 8),
          y: 0.5 * wobble(t * 0.2, 9), nod: 0 };
    }
  }

  function tick(now) {
    if (dead) return;
    frame = requestAnimationFrame(tick);
    // Leaving the page removes the canvas: stop for good. Not yet shown: wait.
    if (!canvas.isConnected) { if (shown) api.destroy(); return; }
    shown = true;
    const calm = reducedMotion();
    const dt = Math.min(0.05, lastDraw ? (now - lastDraw) / 1000 : 0.016);
    lastDraw = now;
    const t = now / 1000;
    const pose = POSES[state] || POSES.ready;

    // ---- lights ----
    const powering = powerStart >= 0 ? t - powerStart : 99;
    for (let i = 0; i < 3; i++) {
      let target = pose.light[i];
      if (target > 0 && powering < 3) {
        const delay = [0, 0.35, 0.7][i];
        const local = powering - delay;
        target = local <= 0 ? 0 : target * Math.min(1, local / 0.5);
        if (i === 0 && local > 0 && local < 0.9 && !calm) {
          // the eyes catch with a stutter before they hold
          target *= (Math.sin(local * 47) + Math.sin(local * 31)) > 0.2 ? 1 : 0.12;
        }
      }
      if (!calm) {
        if (state === 'running' && i > 0) target *= 0.8 + 0.2 * (0.5 + 0.5 * Math.sin(t * 3.3 + i));
        if (state === 'thinking' && i === 0) target *= 0.72 + 0.28 * (0.5 + 0.5 * Math.sin(t * 4.5));
        if (state === 'error' && Math.sin(t * 23 + i * 5) + Math.sin(t * 9.7) > 1.25) target *= 0.15;
      }
      const tau = target < lightNow[i] ? 0.6 : 0.12;      // fade out slower than on
      lightNow[i] += (target - lightNow[i]) * (1 - Math.exp(-dt / tau));
    }
    glowNow += (pose.glow - glowNow) * (1 - Math.exp(-dt / 0.4));

    // ---- body ----
    breathAmp += (pose.breath[0] - breathAmp) * (1 - Math.exp(-dt / 1.2));
    breathPeriod += (pose.breath[1] - breathPeriod) * (1 - Math.exp(-dt / 1.2));
    breathPhase += (dt / breathPeriod) * Math.PI * 2;
    // a breath rises a little faster than it falls
    const b = Math.sin(breathPhase) + 0.25 * Math.sin(breathPhase * 2 - 0.6);
    const breath = calm ? 0 : breathAmp * b * 0.8;

    const target = calm ? { rot: 0, x: 0, y: 0, nod: 0 } : headTarget(t, pose.head);
    if (!calm && pose.head === 'twitch' && t > nextTwitch) {
      head.rot.v += (Math.random() < 0.5 ? -1 : 1) * (0.5 + Math.random() * 0.4);
      head.x.v += (Math.random() - 0.5) * 60;
      nextTwitch = t + 1.4 + Math.random() * 1.8;
    }
    const rot = head.rot.step(target.rot, dt);
    const hx = head.x.step(target.x, dt);
    const hy = head.y.step(target.y, dt);
    const nod = head.nod.step(target.nod, dt);

    // ---- draw ----
    const scale = Math.min(window.devicePixelRatio || 1, lite() ? 1 : 2);
    const w = Math.max(1, Math.round(canvas.clientWidth * scale));
    const h = Math.max(1, Math.round(canvas.clientHeight * scale));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
    gl.viewport(0, 0, w, h);
    gl.uniform3f(uniforms.uLight, lightNow[0], lightNow[1], lightNow[2]);
    gl.uniform1f(uniforms.uGlow, glowNow);
    gl.uniform1f(uniforms.uBreath, breath);
    gl.uniform1f(uniforms.uRot, rot);
    gl.uniform2f(uniforms.uShift, hx, hy);
    gl.uniform1f(uniforms.uNod, nod);
    gl.uniform1f(uniforms.uTime, t);
    // Working: vent again every few seconds, at slightly uneven gaps.
    if (POWERED.has(state) && steamStart < 0 && nextPuff && t >= nextPuff) { steamStart = t; api.puffs += 1; }
    const steam = steamStart >= 0 && !calm ? (t - steamStart) / STEAM_SECONDS : -1;
    gl.uniform1f(uniforms.uSteam, steam >= 1 ? -1 : steam);
    if (steam >= 1) {
      steamStart = -1;
      nextPuff = POWERED.has(state) ? t + PUFF_GAP[0] + Math.random() * (PUFF_GAP[1] - PUFF_GAP[0]) : 0;
    }
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    api.frames += 1;
  }

  canvas.addEventListener('webglcontextlost', (e) => { e.preventDefault(); fail(); });

  api = {
    kind: 'webgl',
    frames: 0,
    puffs: 0,
    setState(next) {
      const was = POWERED.has(state);
      state = POSES[next] ? next : 'ready';
      if (POWERED.has(state) && !was) {
        powerStart = performance.now() / 1000;
        if (steamStart < 0) nextPuff = powerStart + 2;
      }
      if (!POWERED.has(state)) nextPuff = 0;
    },
    steam() { steamStart = performance.now() / 1000; nextPuff = 0; api.puffs += 1; },
    destroy() {
      dead = true;
      cancelAnimationFrame(frame);
      const ext = gl.getExtension('WEBGL_lose_context');
      if (ext) ext.loseContext();
    },
  };

  stage.morvain = api;   // lets the browser tests drive and read it
  Promise.all(Object.entries(SOURCES).map(([key, src]) => loadImage(src).then((img) => [key, img])))
    .then((pairs) => {
      if (dead) return;
      try { setup(Object.fromEntries(pairs)); } catch (err) { fail(); }
    })
    .catch(() => fail());
  return api;
}

export { POWERED };
