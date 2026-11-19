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
 * A small, safe Markdown renderer for the AI summary. It knows only this
 * subset: "#" to "###" headings, numbered and bulleted lists, paragraphs,
 * `inline code` and **bold**. Every node is made with createElement and
 * text nodes (through h() and textContent), so HTML inside the text is
 * shown as text and never interpreted. Anything outside the subset stays
 * plain text, and a marker without its closing pair is kept as typed.
 */
const MD_HEADING = /^ {0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$/;
const MD_NUMBERED = /^\s*(\d{1,9})[.)]\s+(.*)$/;
const MD_BULLET = /^\s*[-*+]\s+(.*)$/;
const MD_RULE = /^\s*([-*_])(?:\s*\1){2,}\s*$/;

/* Inline Markdown (`code` and **bold**) as an array of nodes. */
export function markdownInline(text) {
  const source = String(text === null || text === undefined ? '' : text);
  const nodes = [];
  let plain = '';
  const flush = () => {
    if (plain) nodes.push(document.createTextNode(plain));
    plain = '';
  };
  let i = 0;
  while (i < source.length) {
    if (source[i] === '`') {
      const end = source.indexOf('`', i + 1);
      if (end > i + 1) {
        flush();
        nodes.push(h('code', { text: source.slice(i + 1, end) }));
        i = end + 1;
        continue;
      }
    } else if (source.startsWith('**', i)) {
      const end = source.indexOf('**', i + 2);
      if (end > i + 2) {
        flush();
        // Bold may hold inline code; the text inside is always shorter, so this ends.
        nodes.push(h('strong', {}, markdownInline(source.slice(i + 2, end))));
        i = end + 2;
        continue;
      }
    }
    plain += source[i];
    i += 1;
  }
  flush();
  return nodes;
}

/*
 * Block Markdown as an array of nodes: <h3> for headings, <ol>/<ul> for
 * lists, <p> for paragraphs. classes names the class of each kind:
 * {paragraph, heading, list}. Lines of one paragraph are joined with a
 * space; a blank line ends a paragraph. A blank line between two items
 * keeps one list; an indented line after an item continues that item.
 */
export function markdownNodes(text, classes) {
  const cls = classes || {};
  const blocks = [];
  let para = [];
  let list = null;
  const endPara = () => {
    if (para.length) blocks.push(h('p', { class: cls.paragraph || null }, markdownInline(para.join(' '))));
    para = [];
  };
  const endBlock = () => {
    endPara();
    list = null;
  };
  let table = null;
  const cells = (line) => line.replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
  for (const raw of String(text === null || text === undefined ? '' : text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) {
      endPara();
      table = null;
      continue;
    }
    // A Markdown table: rows of | cells |; the | --- | line under the head is skipped.
    if (line.startsWith('|') && line.endsWith('|') && line.length > 1) {
      if (/^\|[\s:|-]+\|$/.test(line)) continue;
      endBlock();
      if (!table) {
        const head = h('tr', {}, ...cells(line).map((c) => h('th', {}, markdownInline(c))));
        table = { body: h('tbody') };
        blocks.push(h('div', { class: 'md-table-wrap' }, h('table', { class: cls.table || 'md-table' }, h('thead', {}, head), table.body)));
      } else {
        table.body.append(h('tr', {}, ...cells(line).map((c) => h('td', {}, markdownInline(c)))));
      }
      continue;
    }
    table = null;
    if (MD_RULE.test(raw)) {
      endBlock();
      continue;
    }
    const heading = MD_HEADING.exec(raw);
    if (heading) {
      endBlock();
      blocks.push(h('h3', { class: cls.heading || null }, markdownInline(heading[1])));
      continue;
    }
    const numbered = MD_NUMBERED.exec(raw);
    const bullet = numbered ? null : MD_BULLET.exec(raw);
    if (numbered || bullet) {
      endPara();
      const ordered = !!numbered;
      if (!list || list.ordered !== ordered) {
        const attrs = { class: cls.list || null };
        const first = ordered ? Number(numbered[1]) : 1;
        if (first !== 1) attrs.start = String(first);
        list = { ordered, el: h(ordered ? 'ol' : 'ul', attrs) };
        blocks.push(list.el);
      }
      list.el.append(h('li', {}, markdownInline(ordered ? numbered[2] : bullet[1])));
      continue;
    }
    if (list && !para.length && /^\s/.test(raw) && list.el.lastElementChild) {
      list.el.lastElementChild.append(' ', ...markdownInline(line));
      continue;
    }
    list = null;
    para.push(line);
  }
  endPara();
  return blocks;
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
  // The background radar and the logo's signals move only while a scan runs (app.css).
  document.documentElement.classList.toggle('scanning', !!on);
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

/* The run ids history.new_run_id makes; the server checks them again. */
const RUN_ID_SHAPE = /^[0-9]{8}_[0-9]{6}_[A-Za-z0-9._]{1,160}$/;
export function isRunId(value) {
  return typeof value === 'string' && RUN_ID_SHAPE.test(value) && !value.includes('..');
}

/* "12 Nov 2026" and "12 Nov 2026 at 21:36". */
export function formatDay(text) {
  const date = parseTime(text);
  return date ? date.getDate() + ' ' + MONTHS[date.getMonth()] + ' ' + date.getFullYear() : '';
}

export function formatDayTime(text) {
  const date = parseTime(text);
  return date ? formatDay(text) + ' at ' + clock(date) : '';
}

/* "13 min 4 s", "41 s", "1 h 2 min". */
export function formatDuration(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (hours) return hours + ' h ' + minutes + ' min';
  if (minutes) return minutes + ' min ' + (s % 60) + ' s';
  return s + ' s';
}

/* The badge every feature that is not built yet carries. */
export function notBuilt() {
  return h('span', { class: 'notbuilt', text: 'Not built yet' });
}

/* A button for a feature that is not built yet: visible, disabled, and saying so. */
export function notBuiltButton(label, cls) {
  return h('button', {
    type: 'button', class: 'btn ' + (cls || 'quiet'), disabled: true, title: 'Not built yet',
  }, label);
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_WORDS = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown', none: 'No finding',
};
export const severityKey = (s) => (Object.prototype.hasOwnProperty.call(SEVERITY_WORDS, s) ? s : 'none');

/* "Quick scan", "Custom scan" or "Code scan" for an index entry. */
const PRESET_TITLES = { quick: 'Quick scan', standard: 'Standard scan', full: 'Full scan' };
export function entryTitle(entry) {
  if (!entry || typeof entry !== 'object') return 'Scan';
  if (entry.kind === 'code') return 'Code scan';
  if (entry.agent === true) return 'Agent scan';
  if (entry.customized === true) return 'Custom scan';
  return PRESET_TITLES[entry.preset] || 'Scan';
}

/* x on the log scale of DESIGN 5.11, as a percentage. */
export function portX(port) {
  return (Math.log10(Math.max(1, Number(port) || 1)) / Math.log10(65536)) * 100;
}

/*
 * The port spectrum (DESIGN 5.11). ports: [{port, service, severity}].
 * Positions and delays go through the CSSOM, which the Content Security
 * Policy allows; heights and colors come from the severity class in app.css.
 * opts.mini draws the small thumbnail; opts.labels marks critical ports.
 */
export function spectrum(ports, opts) {
  const mini = !!(opts && opts.mini);
  const list = Array.isArray(ports) ? ports.filter((p) => p && Number(p.port) >= 1) : [];
  const counts = {};
  for (const p of list) counts[severityKey(p.severity)] = (counts[severityKey(p.severity)] || 0) + 1;
  const worst = ['critical', 'high', 'medium', 'low'].filter((s) => counts[s])
    .map((s) => counts[s] + ' ' + s).join(', ');
  const label = plural(list.length, 'open port', 'open ports') + (worst ? '. Findings: ' + worst + '.' : '.');
  const box = h('div', { class: mini ? 'mini' : 'spec', role: 'img', 'aria-label': label });
  list.forEach((p, i) => {
    const sev = severityKey(p.severity);
    const service = typeof p.service === 'string' && p.service ? ' ' + p.service : '';
    const tip = p.port + service + ', ' + SEVERITY_WORDS[sev].toLowerCase();
    const bar = h('i', { class: 'sev-' + sev });
    bar.style.animationDelay = ((mini ? 0.3 : 0.35) + i * (mini ? 0.025 : 0.045)).toFixed(3) + 's';
    const tick = h('span', { class: 'tk', 'data-tip': tip }, bar);
    tick.style.left = portX(p.port).toFixed(2) + '%';
    box.append(tick);
    if (!mini && opts && opts.labels && sev === 'critical') {
      const mark = h('span', { class: 'tlabel', text: String(p.port) });
      mark.style.left = portX(p.port).toFixed(2) + '%';
      mark.style.animationDelay = (1.5 + i * 0.05).toFixed(2) + 's';
      box.append(mark);
    }
  });
  return box;
}
