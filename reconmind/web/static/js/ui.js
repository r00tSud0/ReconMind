/*
 * ReconMind UI helpers.
 *
 * Safety rule for every module: data from the server or the user never goes
 * into innerHTML, outerHTML, insertAdjacentHTML or document.write. Static
 * markup lives in index.html (<template> elements, cloned here); everything
 * dynamic is built with h(), which uses createElement and text nodes only.
 */

/* Append children: nodes as they are, anything else as a text node. */
function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

/*
 * h('div', {class: 'x', onclick: fn}, 'text', otherNode)
 * attrs: class, text (textContent), style (an object set through the CSSOM,
 * which the Content Security Policy allows), on<event> functions, and plain
 * attributes. true sets an empty attribute; false, null and undefined skip it.
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = String(value);
    else if (key === 'style') {
      for (const [prop, val] of Object.entries(value)) el.style.setProperty(prop, String(val));
    } else if (key.startsWith('on')) {
      // Only real functions become listeners; a string handler would be inline script.
      if (typeof value === 'function') el.addEventListener(key.slice(2), value);
    } else if (value === true) el.setAttribute(key, '');
    else el.setAttribute(key, String(value));
  }
  return append(el, children);
}

/*
 * Clone a <template> from index.html. Returns {root, refs}: root is the
 * template's first element, refs maps every data-ref name to its element.
 */
export function clone(id) {
  const tpl = document.getElementById(id);
  const fragment = tpl.content.cloneNode(true);
  const root = fragment.firstElementChild;
  const refs = {};
  for (const el of root.querySelectorAll('[data-ref]')) refs[el.dataset.ref] = el;
  return { root, refs };
}

/* A heat meter (DESIGN 5.8): four cells, filled by severity, with a label. */
export function heat(severity) {
  const el = h('span', { class: 'heat ' + severity, role: 'img', 'aria-label': severity });
  for (let i = 0; i < 4; i += 1) el.append(document.createElement('i'));
  return el;
}

export function reducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/* Count a number up once (DESIGN 6); shows the final value at once under reduced motion. */
export function countUp(el, target) {
  const end = Number(target) || 0;
  if (reducedMotion() || end <= 0) {
    el.textContent = String(end);
    return;
  }
  const started = performance.now();
  const duration = 900;
  const step = (now) => {
    const t = Math.min(1, (now - started) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = String(Math.round(end * eased));
    if (t < 1) requestAnimationFrame(step);
  };
  el.textContent = '0';
  requestAnimationFrame(step);
}

/* The banner under the top bar when the server does not answer. */
export function serverDown(down) {
  const banner = document.getElementById('server-error');
  if (banner) banner.hidden = !down;
}

/* The pulsing dot on the Live run nav item while a scan runs. */
export function setLive(on) {
  const dot = document.getElementById('live-dot');
  if (dot) dot.hidden = !on;
}

/* "a, b, c and d" */
export function joinList(items) {
  const list = Array.from(items || [], String);
  if (list.length <= 1) return list.join('');
  return list.slice(0, -1).join(', ') + ' and ' + list[list.length - 1];
}

export function plural(n, one, many) {
  return n + ' ' + (n === 1 ? one : many);
}

/* The server writes local times as "YYYY-MM-DDTHH:MM:SS", which Date reads as local. */
export function parseTime(text) {
  if (typeof text !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(text)) return null;
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function clock(date) {
  return String(date.getHours()).padStart(2, '0') + ':' + String(date.getMinutes()).padStart(2, '0');
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/* "Today 21:49" or "12 Nov 21:49". */
export function formatWhen(text) {
  const date = parseTime(text);
  if (!date) return '';
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  const day = sameDay ? 'Today' : date.getDate() + ' ' + MONTHS[date.getMonth()];
  return day + ' ' + clock(date);
}

/* "4:07" or "1:02:09". */
export function formatElapsed(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = String(s % 60).padStart(2, '0');
  return hours ? hours + ':' + String(minutes).padStart(2, '0') + ':' + secs : minutes + ':' + secs;
}

export function basename(path) {
  const parts = String(path || '').replace(/[\\/]+$/, '').split(/[\\/]/);
  return parts[parts.length - 1] || String(path || '');
}

export const JOB_ID = /^[0-9a-f]{12}$/;
