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
 * slow organic noise, so it eases, overshoots a little and settles. It always
 * breathes. The lights are mixed between the portrait and its powered down
 * version, per group (eyes, head, body), so they come on with a flicker and
 * fade out.
 *
 *   Working (thinking, running, waiting for approval): red lights, and steam
 *   puffs from behind it every few seconds.
 *   Answering your question: the lights turn yellow and sparks fly from
 *   behind it. No steam.
 *   Off (ready, finished, stopped): lights off, no steam, still breathing.
 *
 * It runs the same on every computer, with no setting to pick, and is kept
 * light so it stays smooth in a virtual machine too: the canvas is never
 * drawn larger than MAX_PIXELS wide, it draws only while it is on screen,
 * and when frames start coming slowly it draws every other frame (about 30
 * a second), which still looks smooth for motion this slow. It also ignores
 * the system's reduce motion setting (Windows turns that on when its
 * animation effects are off): MORVAIN-X0's motion is slow and small, and it
 * is how the agent shows what it is doing.
 *
 * Without WebGL (or after a lost WebGL context) a plain 2D canvas draws the
 * same states: the robot breathes over a still background, the lights fade
 * red or yellow, steam and sparks rise behind it. Only if that fails too is
 * a still portrait shown.
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
const VENTS = [[640 * 0.16, 800 * 0.60], [640 * 0.84, 800 * 0.60]];
const STEAM_SECONDS = 3.2;
// While working, a new puff starts this many seconds after the last one ends.
const PUFF_GAP = [1.2, 3.2];
const SPARKS = 26;
const YELLOW = [1.0, 0.82, 0.28];
const ALT = 'MORVAIN-X0, a black chrome robotic face with red optics';

const VERT = `
attribute vec2 aPos;
varying vec2 vUv;
void main() {
  vUv = vec2(aPos.x * 0.5 + 0.5, 0.5 - aPos.y * 0.5);
  gl_Position = vec4(aPos, 0.0, 1.0);
}`;

const FRAG = `
#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif
varying vec2 vUv;
uniform sampler2D uLit, uOff, uMask, uWeight;
uniform vec2 uSize, uPivot, uShift;
uniform float uRot, uNod, uBreath, uGlow, uSteam, uTime, uTint, uSpark;
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
  // The lights are the portrait's red; answering turns them yellow.
  vec3 diff = (lit - off) * k;
  vec3 pos = max(diff, vec3(0.0));
  vec3 yellow = max(pos.r, max(pos.g, pos.b)) * vec3(1.0, 0.82, 0.28);
  vec3 light = mix(diff, yellow, uTint);
  vec3 col = off + light * (1.0 + uGlow);
  float behind = 1.0 - 0.75 * m.a;   // mostly behind the robot, a thin veil in front

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
    vec3 vapour = vec3(0.74, 0.74, 0.79) + vec3(0.18, 0.0, 0.01) * uLight.y;
    col = mix(col, vapour, clamp(dens * env * behind * 0.85, 0.0, 0.7));
  }

  // Sparks: short hot streaks thrown from behind the shoulders, falling as they fade.
  if (uSpark > 0.001) {
    vec3 glow = vec3(0.0);
    for (int i = 0; i < ${SPARKS}; i++) {
      float fi = float(i);
      float side = mod(fi, 2.0) < 1.0 ? -1.0 : 1.0;
      float period = 0.7 + 0.6 * hash(vec2(fi, 3.1));
      float tt = uTime / period + hash(vec2(fi, 7.7));
      float cyc = floor(tt);
      float life = fract(tt);
      if (hash(vec2(fi, cyc)) < 0.4) continue;   // not every spark fires every time
      vec2 o = vec2(uSize.x * (0.5 + side * (0.29 + 0.07 * hash(vec2(cyc, fi)))),
                    uSize.y * (0.55 + 0.07 * hash(vec2(fi, cyc + 1.0))));
      vec2 v = vec2(side * (90.0 + 210.0 * hash(vec2(cyc, fi + 2.0))),
                    -(160.0 + 280.0 * hash(vec2(fi + 5.0, cyc))));
      float age = life * period * 0.8;
      vec2 at = o + v * age + vec2(0.0, 430.0) * age * age;
      vec2 vel = v + vec2(0.0, 860.0) * age;
      vec2 tail = at - vel * 0.07;
      vec2 pa = p - tail, ba = at - tail;
      float h = clamp(dot(pa, ba) / max(dot(ba, ba), 0.001), 0.0, 1.0);
      float dist = length(pa - ba * h);
      float fade = pow(1.0 - life, 1.5);
      vec3 hot = mix(vec3(1.0, 0.95, 0.7), vec3(1.0, 0.55, 0.12), life);
      glow += hot * fade * (1.6 * exp(-dist * dist / 9.0) + 0.45 * exp(-dist * dist / 90.0));
    }
    col += glow * uSpark * (1.0 - 0.85 * m.a);
  }
  gl_FragColor = vec4(min(col, vec3(1.0)), 1.0);
}`;

/* What each agent state asks of the body. light: eyes, head lights, body lights.
   tint: 0 red, 1 yellow. spark: sparks behind it. steam: puffs while powered. */
const POSES = {
  ready:     { light: [0, 0, 0],      glow: 0,    breath: [0.55, 5.6], head: 'rest',   tint: 0, spark: 0, steam: false },
  thinking:  { light: [1, 0.85, 0.7], glow: 0.1,  breath: [0.8, 4.4],  head: 'think',  tint: 0, spark: 0, steam: true },
  running:   { light: [1, 1, 1],      glow: 0.22, breath: [1.0, 3.4],  head: 'scan',   tint: 0, spark: 0, steam: true },
  awaiting:  { light: [1, 1, 0.9],    glow: 0.14, breath: [0.7, 5.0],  head: 'attend', tint: 0, spark: 0, steam: true },
  answering: { light: [1, 1, 0.95],   glow: 0.2,  breath: [0.8, 4.2],  head: 'think',  tint: 1, spark: 1, steam: false },
  done:      { light: [1, 0.8, 0.75], glow: 0.08, breath: [0.6, 5.2],  head: 'rest',   tint: 0, spark: 0, steam: true },
  error:     { light: [1, 1, 1],      glow: 0.18, breath: [0.9, 3.8],  head: 'twitch', tint: 0, spark: 0, steam: true },
  finished:  { light: [0, 0, 0],      glow: 0,    breath: [0.5, 6.0],  head: 'rest',   tint: 0, spark: 0, steam: false },
  stopped:   { light: [0, 0, 0],      glow: 0,    breath: [0.5, 6.0],  head: 'rest',   tint: 0, spark: 0, steam: false },
};
const POWERED = new Set(['thinking', 'running', 'awaiting', 'answering', 'done', 'error']);

// Smooth noise in time: a few sines at unrelated speeds never quite repeat.
const wobble = (t, seed) => (Math.sin(t * 0.73 + seed) * 0.5 + Math.sin(t * 1.31 + seed * 2.1) * 0.3
  + Math.sin(t * 2.17 + seed * 3.7) * 0.2);
// The same hash as the shader's, for the 2D canvas.
const hash = (x, y) => { const v = Math.sin(x * 127.1 + y * 311.7) * 43758.5453; return v - Math.floor(v); };

function loadImage(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.decoding = 'async';
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('could not load ' + src));
    img.src = src;
  });
}

const MAX_PIXELS = 480;      // widest the canvas is ever drawn, in device pixels
const SLOW_FRAME_MS = 24;    // frames slower than this on average: draw every other one

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
  // Last resort: the lit portrait under the powered down one; the lights fade in and out.
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

/* ---- the 2D canvas renderer (no WebGL) -------------------------------- */

function layer() {
  const c = document.createElement('canvas');
  c.width = SIZE[0];
  c.height = SIZE[1];
  return c;
}

/* From the portrait and its maps: the robot cut out of the powered down
   picture, and its lights as red and as yellow, to add on top. */
function canvasLayers(images) {
  const read = (img) => {
    const c = layer();
    const x = c.getContext('2d');
    x.drawImage(img, 0, 0, SIZE[0], SIZE[1]);
    return x.getImageData(0, 0, SIZE[0], SIZE[1]);
  };
  const lit = read(images.lit).data;
  const off = read(images.off).data;
  const mask = read(images.mask).data;
  const robot = layer();
  const red = layer();
  const yellow = layer();
  const rd = robot.getContext('2d').createImageData(SIZE[0], SIZE[1]);
  const re = red.getContext('2d').createImageData(SIZE[0], SIZE[1]);
  const ye = yellow.getContext('2d').createImageData(SIZE[0], SIZE[1]);
  for (let i = 0; i < lit.length; i += 4) {
    rd.data[i] = off[i]; rd.data[i + 1] = off[i + 1]; rd.data[i + 2] = off[i + 2];
    rd.data[i + 3] = mask[i + 3];
    const k = Math.max(mask[i], mask[i + 1], mask[i + 2]) / 255;
    const r = Math.max(0, lit[i] - off[i]) * k;
    const g = Math.max(0, lit[i + 1] - off[i + 1]) * k;
    const b = Math.max(0, lit[i + 2] - off[i + 2]) * k;
    re.data[i] = r; re.data[i + 1] = g; re.data[i + 2] = b; re.data[i + 3] = 255;
    const top = Math.max(r, g, b);
    ye.data[i] = top * YELLOW[0]; ye.data[i + 1] = top * YELLOW[1]; ye.data[i + 2] = top * YELLOW[2];
    ye.data[i + 3] = 255;
  }
  robot.getContext('2d').putImageData(rd, 0, 0);
  red.getContext('2d').putImageData(re, 0, 0);
  yellow.getContext('2d').putImageData(ye, 0, 0);
  return { background: images.off, robot, red, yellow };
}

function draw2d(ctx, layers, f, w, h) {
  ctx.setTransform(w / SIZE[0], 0, 0, h / SIZE[1], 0, 0);
  ctx.globalCompositeOperation = 'source-over';
  ctx.globalAlpha = 1;
  ctx.drawImage(layers.background, 0, 0, SIZE[0], SIZE[1]);
  // Steam behind the robot: soft puffs that rise, widen and fade.
  if (f.steam >= 0 && f.steam < 1) {
    const age = f.steam * STEAM_SECONDS;
    for (const [vx, vy] of VENTS) {
      const side = vx < SIZE[0] / 2 ? -1 : 1;
      for (let i = 0; i < 10; i++) {
        const a = age - i * 0.14;
        if (a <= 0 || a > 2.4) continue;
        const x = vx + side * (6 + a * 18) + Math.sin(a * 3 + i) * 8;
        const y = vy - a * 120 - i * 4;
        const r = 14 + a * 34;
        const alpha = 0.32 * Math.min(1, a / 0.3) * (1 - a / 2.4);
        const g = ctx.createRadialGradient(x, y, 0, x, y, r);
        g.addColorStop(0, 'rgba(205,205,215,' + alpha.toFixed(3) + ')');
        g.addColorStop(1, 'rgba(205,205,215,0)');
        ctx.fillStyle = g;
        ctx.fillRect(x - r, y - r, r * 2, r * 2);
      }
    }
  }
  // Sparks behind the robot, the same streaks the shader draws.
  if (f.spark > 0.001) {
    ctx.globalCompositeOperation = 'lighter';
    ctx.lineCap = 'round';
    for (let i = 0; i < SPARKS; i++) {
      const side = i % 2 ? 1 : -1;
      const period = 0.7 + 0.6 * hash(i, 3.1);
      const tt = f.time / period + hash(i, 7.7);
      const cyc = Math.floor(tt);
      const life = tt - cyc;
      if (hash(i, cyc) < 0.4) continue;
      const ox = SIZE[0] * (0.5 + side * (0.29 + 0.07 * hash(cyc, i)));
      const oy = SIZE[1] * (0.55 + 0.07 * hash(i, cyc + 1));
      const vx = side * (90 + 210 * hash(cyc, i + 2));
      const vy = -(160 + 280 * hash(i + 5, cyc));
      const age = life * period * 0.8;
      const x = ox + vx * age;
      const y = oy + vy * age + 430 * age * age;
      const tx = x - vx * 0.07;
      const ty = y - (vy + 860 * age) * 0.07;
      const fade = Math.pow(1 - life, 1.5) * f.spark;
      const color = 'rgba(255,' + Math.round(240 - 110 * life) + ',' + Math.round(170 - 140 * life) + ',';
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(x, y);
      ctx.strokeStyle = color + (fade * 0.3).toFixed(3) + ')';   // the glow
      ctx.lineWidth = 11;
      ctx.stroke();
      ctx.strokeStyle = color + Math.min(1, fade * 1.4).toFixed(3) + ')';   // the hot core
      ctx.lineWidth = 4;
      ctx.stroke();
    }
    ctx.globalCompositeOperation = 'source-over';
  }
  // The robot breathes over the still background; the head rides along.
  const lift = -1.7 * f.breath;
  const widen = 1 + 0.0035 * f.breath;
  ctx.setTransform((w / SIZE[0]) * widen, 0, 0, h / SIZE[1], (w / SIZE[0]) * (SIZE[0] / 2) * (1 - widen),
    (h / SIZE[1]) * lift);
  ctx.translate(PIVOT[0], PIVOT[1]);
  ctx.rotate(f.rot * 0.35);
  ctx.translate(-PIVOT[0] + f.hx * 0.35, -PIVOT[1] + f.hy * 0.35);
  ctx.drawImage(layers.robot, 0, 0);
  const lights = (f.light[0] + f.light[1] + f.light[2]) / 3 * (1 + f.glow);
  if (lights > 0.01) {
    ctx.globalCompositeOperation = 'lighter';
    ctx.globalAlpha = Math.min(1, lights * (1 - f.tint));
    if (ctx.globalAlpha > 0.01) ctx.drawImage(layers.red, 0, 0);
    ctx.globalAlpha = Math.min(1, lights * f.tint);
    if (ctx.globalAlpha > 0.01) ctx.drawImage(layers.yellow, 0, 0);
  }
  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = 'source-over';
}

/* ---- the character ---------------------------------------------------- */

export function createMorvain(stage, onMissing) {
  let canvas = document.createElement('canvas');
  canvas.className = 'mx-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  let gl = null;
  let ctx2d = null;
  let layers2d = null;
  try {
    gl = canvas.getContext('webgl', { antialias: false, alpha: false, premultipliedAlpha: false,
      powerPreference: 'low-power' }) || canvas.getContext('experimental-webgl');
  } catch (err) {
    gl = null;
  }

  // Until the images arrive, the still portrait shows in place.
  const still = document.createElement('img');
  still.className = 'mx-still';
  still.src = SOURCES.off;
  still.alt = ALT;
  stage.replaceChildren(still, canvas);

  let program = null;
  const uniforms = {};
  let images = null;
  let dead = false;
  let frame = 0;
  let lastDraw = 0;
  let state = 'ready';
  let steamStart = -1;
  let nextPuff = 0;
  let powerStart = -1;
  let shown = false;
  let onScreen = true;
  let offChecks = 0;
  let halfRate = false;        // frames are coming slowly: draw every other one
  let warm = 0;               // frames seen; the first 60 (page load) are not timed
  let skip = false;
  const gaps = [];             // recent frame gaps, to notice a slow computer
  let lastFrame = 0;
  const lightNow = [0, 0, 0];
  let glowNow = 0;
  let tintNow = 0;
  let sparkNow = 0;
  let breathPhase = 0;
  let breathAmp = 0.55;
  let breathPeriod = 5.6;
  const head = { rot: spring(16, 6.5), x: spring(14, 6), y: spring(14, 6), nod: spring(12, 6) };
  let nextTwitch = 0;
  let api = null;

  const vents = () => POWERED.has(state) && (POSES[state] || POSES.ready).steam;
  const gap = () => PUFF_GAP[0] + Math.random() * (PUFF_GAP[1] - PUFF_GAP[0]);

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

  function stillOnly(why) {
    if (dead) return;
    dead = true;
    cancelAnimationFrame(frame);
    if (typeof console !== 'undefined') console.warn('MORVAIN-X0: still portrait (' + why + ')');
    const fallback = stillFallback(stage, onMissing);
    fallback.setState(state);
    api.kind = 'still';
    api.setState = fallback.setState;
  }

  /* No WebGL, or it failed: the 2D canvas draws the same states. */
  function use2d(why) {
    if (dead || ctx2d) return;
    if (typeof console !== 'undefined') console.warn('MORVAIN-X0: 2D canvas (' + why + ')');
    gl = null;
    const fresh = document.createElement('canvas');
    fresh.className = 'mx-canvas';
    fresh.setAttribute('aria-hidden', 'true');
    canvas.replaceWith(fresh);
    canvas = fresh;
    watch();
    try {
      ctx2d = canvas.getContext('2d');
      if (!ctx2d) throw new Error('no 2D canvas');
      api.kind = 'canvas';
      if (images) start2d();
    } catch (err) {
      stillOnly(String(err && err.message));
    }
  }

  function start2d() {
    try {
      layers2d = canvasLayers(images);
    } catch (err) {
      stillOnly(String(err && err.message));
      return;
    }
    still.remove();
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(tick);
  }

  function setupGl() {
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
      'uNod', 'uBreath', 'uGlow', 'uSteam', 'uTime', 'uLight', 'uTint', 'uSpark']) {
      uniforms[name] = gl.getUniformLocation(program, name);
    }
    ['lit', 'off', 'mask', 'weight'].forEach((key, i) => {
      texture(i, images[key]);
      gl.uniform1i(uniforms['u' + key.charAt(0).toUpperCase() + key.slice(1)], i);
    });
    gl.uniform2f(uniforms.uSize, SIZE[0], SIZE[1]);
    gl.uniform2f(uniforms.uPivot, PIVOT[0], PIVOT[1]);
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

  function visible() {
    const r = canvas.getBoundingClientRect();
    return r.width > 0 && r.bottom > 0 && r.right > 0
      && r.top < (window.innerHeight || 0) && r.left < (window.innerWidth || 0);
  }

  function tick(now) {
    if (dead) return;
    frame = requestAnimationFrame(tick);
    // Leaving the page removes the canvas: stop for good. Not yet shown: wait.
    if (!canvas.isConnected) { if (shown) api.destroy(); return; }
    shown = true;
    if (!onScreen) {
      // The observer said it is out of view; check now and then in case it missed coming back.
      offChecks += 1;
      if (offChecks % 30 === 0 && visible()) onScreen = true;
      if (!onScreen) { lastFrame = 0; warm = 0; gaps.length = 0; return; }
    }
    // Watch the frame gaps (after the page settles): a slow computer draws
    // every other frame, and goes back to every frame if it speeds up.
    if (lastFrame) {
      warm += 1;
      if (warm > 60) {
        gaps.push(now - lastFrame);
        if (gaps.length > 120) gaps.shift();
        if (gaps.length === 120) halfRate = gaps.reduce((a, b) => a + b, 0) / 120 > SLOW_FRAME_MS;
      }
    }
    lastFrame = now;
    if (halfRate) { skip = !skip; if (skip) return; }
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
        if (i === 0 && local > 0 && local < 0.9) {
          // the eyes catch with a stutter before they hold
          target *= (Math.sin(local * 47) + Math.sin(local * 31)) > 0.2 ? 1 : 0.12;
        }
      }
      if (state === 'running' && i > 0) target *= 0.8 + 0.2 * (0.5 + 0.5 * Math.sin(t * 3.3 + i));
      if (state === 'thinking' && i === 0) target *= 0.72 + 0.28 * (0.5 + 0.5 * Math.sin(t * 4.5));
      if (state === 'answering') target *= 0.82 + 0.18 * (0.5 + 0.5 * Math.sin(t * 6.2 + i * 1.7));
      if (state === 'error' && Math.sin(t * 23 + i * 5) + Math.sin(t * 9.7) > 1.25) target *= 0.15;
      const tau = target < lightNow[i] ? 0.6 : 0.12;      // fade out slower than on
      lightNow[i] += (target - lightNow[i]) * (1 - Math.exp(-dt / tau));
    }
    glowNow += (pose.glow - glowNow) * (1 - Math.exp(-dt / 0.4));
    tintNow += (pose.tint - tintNow) * (1 - Math.exp(-dt / 0.35));
    sparkNow += (pose.spark - sparkNow) * (1 - Math.exp(-dt / (pose.spark ? 0.25 : 0.5)));

    // ---- body: it always breathes ----
    breathAmp += (pose.breath[0] - breathAmp) * (1 - Math.exp(-dt / 1.2));
    breathPeriod += (pose.breath[1] - breathPeriod) * (1 - Math.exp(-dt / 1.2));
    breathPhase += (dt / breathPeriod) * Math.PI * 2;
    // a breath rises a little faster than it falls
    const b = Math.sin(breathPhase) + 0.25 * Math.sin(breathPhase * 2 - 0.6);
    const breath = breathAmp * b * 0.8;

    const target = headTarget(t, pose.head);
    if (pose.head === 'twitch' && t > nextTwitch) {
      head.rot.v += (Math.random() < 0.5 ? -1 : 1) * (0.5 + Math.random() * 0.4);
      head.x.v += (Math.random() - 0.5) * 60;
      nextTwitch = t + 1.4 + Math.random() * 1.8;
    }
    const rot = head.rot.step(target.rot, dt);
    const hx = head.x.step(target.x, dt);
    const hy = head.y.step(target.y, dt);
    const nod = head.nod.step(target.nod, dt);

    // ---- steam: while working it vents again every few seconds, at uneven gaps ----
    const venting = vents();
    if (venting && steamStart < 0 && !nextPuff) nextPuff = t + gap();
    if (venting && steamStart < 0 && nextPuff && t >= nextPuff) { steamStart = t; api.puffs += 1; }
    let steam = steamStart >= 0 ? (t - steamStart) / STEAM_SECONDS : -1;
    if (steam >= 1) {
      steamStart = -1;
      steam = -1;
      nextPuff = venting ? t + gap() : 0;
    }

    // ---- draw ----
    const scale = Math.min(window.devicePixelRatio || 1, 1.5,
      MAX_PIXELS / Math.max(1, canvas.clientWidth));
    const w = Math.max(1, Math.round(canvas.clientWidth * scale));
    const h = Math.max(1, Math.round(canvas.clientHeight * scale));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
    const time = t % 600;   // keeps the shader's numbers small
    if (gl) {
      gl.viewport(0, 0, w, h);
      gl.uniform3f(uniforms.uLight, lightNow[0], lightNow[1], lightNow[2]);
      gl.uniform1f(uniforms.uGlow, glowNow);
      gl.uniform1f(uniforms.uTint, tintNow);
      gl.uniform1f(uniforms.uSpark, sparkNow);
      gl.uniform1f(uniforms.uBreath, breath);
      gl.uniform1f(uniforms.uRot, rot);
      gl.uniform2f(uniforms.uShift, hx, hy);
      gl.uniform1f(uniforms.uNod, nod);
      gl.uniform1f(uniforms.uTime, time);
      gl.uniform1f(uniforms.uSteam, steam);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    } else if (ctx2d && layers2d) {
      draw2d(ctx2d, layers2d, { light: lightNow, glow: glowNow, tint: tintNow, spark: sparkNow,
        breath, rot, hx, hy, steam, time }, w, h);
    }
    api.frames += 1;
  }

  // Scrolled out of view: stop drawing until it comes back.
  let observer = null;
  function watch() {
    if (typeof IntersectionObserver !== 'function') return;
    if (observer) observer.disconnect();
    observer = new IntersectionObserver((entries) => {
      onScreen = entries.some((e) => e.isIntersecting);
    });
    observer.observe(canvas);
  }
  watch();
  canvas.addEventListener('webglcontextlost', (e) => { e.preventDefault(); use2d('WebGL context lost'); });

  api = {
    kind: gl ? 'webgl' : 'canvas',
    frames: 0,
    puffs: 0,
    setState(next) {
      const was = POWERED.has(state);
      state = POSES[next] ? next : 'ready';
      if (POWERED.has(state) && !was) {
        powerStart = performance.now() / 1000;
        if (steamStart < 0) nextPuff = powerStart + 2;
      }
      if (!vents()) nextPuff = 0;
    },
    state: () => state,
    steam() { steamStart = performance.now() / 1000; nextPuff = 0; api.puffs += 1; },
    destroy() {
      dead = true;
      cancelAnimationFrame(frame);
      if (observer) observer.disconnect();
      const ext = gl && gl.getExtension('WEBGL_lose_context');
      if (ext) ext.loseContext();
    },
  };

  stage.morvain = api;   // lets the browser tests drive and read it
  if (!gl) use2d('no WebGL');
  Promise.all(Object.entries(SOURCES).map(([key, src]) => loadImage(src).then((img) => [key, img])))
    .then((pairs) => {
      if (dead) return;
      images = Object.fromEntries(pairs);
      if (gl) {
        try { setupGl(); } catch (err) { use2d(String(err && err.message)); }
      } else if (ctx2d) {
        start2d();
      }
    })
    .catch((err) => stillOnly(String(err && err.message)));
  return api;
}

export { POWERED };
