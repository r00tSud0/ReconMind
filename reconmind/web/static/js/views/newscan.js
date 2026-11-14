/*
 * New scan view (#/new), matching docs/design/screens/01_Main.html.
 *
 * Presets, their actions, ports and nuclei mode, the action names and the
 * allowlist all come from /api/options; only the descriptions below are
 * copy, taken word for word from DESIGN.md section 7. The page never decides
 * what is allowed: Start sends the request to /api/check, which runs the
 * authorization gate and the scan plan checks on the server, and only then
 * to /api/scans.
 *
 * Ticking an action changes the shown preset to Custom, but the request
 * still sends the base preset id plus the actions list, which is exactly how
 * the CLI reads --preset with --actions.
 */

import * as api from '../api.js';
import {
  basename, clone, countUp, formatWhen, h, heat, JOB_ID, joinList, parseTime, clock, plural,
  reducedMotion,
} from '../ui.js';

const ACTION_COPY = {
  surface: { tool: 'nmap', desc: 'Scans the target with nmap to find which TCP ports are open and which service and version runs on each. Always runs.' },
  exploits: { tool: 'searchsploit', desc: 'Searches Exploit-DB for public exploits that match each service and version nmap found, marks whether the version match is exact, and flags services that are risky just by being exposed.' },
  cves: { tool: 'NVD', desc: 'Looks up each service version in the NVD database and lists its known CVEs with CVSS scores. Flags any that CISA lists as actively exploited.' },
  web: { tool: 'httpx', desc: 'Connects to each web port and identifies the web server, frameworks and technologies in use, plus which security headers are missing.' },
  paths: { tool: 'ffuf', desc: 'Requests a list of common file and folder names on each web port to find pages that exist but are not linked, such as admin panels.' },
  vulns: { tool: 'nuclei', desc: 'Runs nuclei templates against web services to confirm known vulnerabilities and misconfigurations. Safe templates only, no DoS or fuzzing.' },
  crypto: { tool: 'testssl.sh', desc: 'Tests every TLS port, including STARTTLS, for outdated protocol versions, weak ciphers and certificate problems.' },
  smb: { tool: 'enum4linux-ng', desc: 'Connects to SMB without a password and lists the shares, users, groups and domain details an anonymous user can see.' },
};

const PRESET_COPY = {
  quick: { name: 'Quick', desc: 'Scans the top 1000 ports, then checks each service for public exploits and known CVEs.' },
  standard: { name: 'Standard', desc: 'Scans the top 1000 ports and runs all 8 actions. Nuclei only runs templates that match the technology it detects.' },
  full: { name: 'Full report', desc: 'Scans all 65535 ports and runs all 8 actions with every safe nuclei template. One host at a time.' },
};

const ALWAYS_ON = 'surface';
const MODES = ['host', 'list', 'code'];
const PORT_CHOICES = ['top', 'all', 'custom'];
const FIELDS = ['target', 'ports', 'path', 'actions'];
const RECON_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const CODE_SEVERITIES = ['high', 'medium', 'low'];
const SEVERITY_WORDS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const PRESET_TITLES = { quick: 'Quick scan', standard: 'Standard scan', full: 'Full report' };

export function mountNewScan(view) {
  const { root, refs } = clone('tpl-newscan');
  view.append(root);

  const targetInput = root.querySelector('#target');
  const hostsInput = root.querySelector('#hosts');
  const pathInput = root.querySelector('#path');
  const portsInput = root.querySelector('#ports');
  const explainInput = root.querySelector('#explain');
  const modeButtons = Array.from(root.querySelectorAll('[data-mode]'));
  const portButtons = Array.from(root.querySelectorAll('[data-ports]'));
  const modeInd = root.querySelector('.seg-mode .ind');
  const portInd = root.querySelector('.seg-ports .ind');

  const state = {
    mode: 'host',
    base: null,      // the preset id the request sends
    sel: [],         // ticked action ids, in /api/options order
    ports: 'top',    // top, all or custom
    explain: false,
    busy: false,
    opts: null,
  };
  const presetCards = {};
  const actionRows = {};
  let alive = true;
  let lastPlan = '';

  // ---- options and helpers ---------------------------------------------

  const preset = (id) => (state.opts ? state.opts.presets.find((p) => p.id === id) : null);
  const actionIds = () => state.opts.actions.map((a) => a.id);
  const presetName = (id) => (PRESET_COPY[id] ? PRESET_COPY[id].name : id);
  // Presets that scan every port are for one host at a time.
  const presetAllowed = (p) => !(state.mode === 'list' && p.ports === 'all');

  // "22, 80" and "22,80" mean the same; the server still checks the spec itself.
  function customPorts() {
    return portsInput.value.replace(/\s+/g, '');
  }

  function portsValue() {
    return state.ports === 'custom' ? customPorts() : state.ports;
  }

  function sameSet(a, b) {
    return a.length === b.length && a.every((x) => b.includes(x));
  }

  // The shown preset is the base one only while nothing differs from it.
  function shownPreset() {
    const p = preset(state.base);
    if (!p) return 'custom';
    return sameSet(state.sel, p.actions) && portsValue() === p.ports ? p.id : 'custom';
  }

  function hostLines() {
    return hostsInput.value.split('\n').map((s) => s.trim()).filter(Boolean);
  }

  // ---- state changes ---------------------------------------------------

  function applyPreset(id) {
    const p = preset(id);
    if (!p || !presetAllowed(p)) return;
    state.base = p.id;
    state.sel = p.actions.slice();
    if (p.ports === 'top' || p.ports === 'all') {
      state.ports = p.ports;
    } else {
      state.ports = 'custom';
      portsInput.value = p.ports;
    }
  }

  function setMode(mode) {
    if (!MODES.includes(mode) || mode === state.mode) return;
    if (mode === 'list') {
      // A preset that scans every port is not offered for a list.
      const p = preset(state.base);
      if (p && p.ports === 'all') {
        const fallback = preset(state.opts.default_preset);
        applyPreset(fallback && fallback.ports !== 'all' ? fallback.id
          : state.opts.presets.find((x) => x.ports !== 'all').id);
      }
      if (state.ports === 'all') state.ports = 'top';
    }
    state.mode = mode;
    clearProblems();
  }

  function toggleAction(id, on) {
    if (id === ALWAYS_ON) return;
    const chosen = new Set(state.sel);
    if (on) chosen.add(id);
    else chosen.delete(id);
    chosen.add(ALWAYS_ON);
    state.sel = actionIds().filter((a) => chosen.has(a));
    clearFieldError('actions');
  }

  function pickPorts(choice) {
    if (!PORT_CHOICES.includes(choice)) return;
    if (state.mode === 'list' && choice === 'all') return;
    state.ports = choice;
    clearFieldError('ports');
  }

  // ---- building the lists from /api/options ----------------------------

  function buildPresets() {
    refs.presets.replaceChildren();
    for (const p of state.opts.presets) {
      const copy = PRESET_COPY[p.id] || { name: p.id, desc: '' };
      const card = h('button', {
        type: 'button',
        class: 'preset',
        'aria-pressed': 'false',
        onclick: () => { applyPreset(p.id); render(); },
      },
      h('span', { class: 'dot', 'aria-hidden': 'true' }),
      h('span', { class: 'preset-text' },
        h('span', { class: 'preset-name', text: copy.name }),
        h('span', { class: 'preset-desc', text: copy.desc })));
      presetCards[p.id] = card;
      refs.presets.append(card);
    }
  }

  function buildActions() {
    refs.actions.replaceChildren();
    for (const a of state.opts.actions) {
      const copy = ACTION_COPY[a.id] || { tool: a.tools.join(', '), desc: '' };
      const locked = a.id === ALWAYS_ON;
      const box = h('input', {
        type: 'checkbox',
        class: 'ck',
        disabled: locked,
        'aria-describedby': 'act-desc-' + a.id,
        onchange: (event) => { toggleAction(a.id, event.target.checked); render(); },
      });
      const row = h('label', { class: 'act' + (locked ? ' locked' : '') },
        box,
        h('span', { class: 'act-text' },
          h('span', {},
            h('span', { class: 'act-name', text: a.name }),
            h('span', { class: 'tag act-tool', text: copy.tool })),
          h('span', { class: 'act-desc', id: 'act-desc-' + a.id, text: copy.desc })));
      actionRows[a.id] = { row, box };
      refs.actions.append(row);
    }
  }

  // ---- rendering -------------------------------------------------------

  function planSentence() {
    if (state.mode === 'code') {
      const path = pathInput.value.trim();
      const what = path ? basename(path) : 'the code';
      return 'Read ' + what + ' with Semgrep and Bandit'
        + (state.explain ? ', then explain each finding with AI.' : '. No AI explanation.');
    }
    if (!state.opts) return 'Loading the scan options.';
    let who;
    if (state.mode === 'list') {
      const n = hostLines().length;
      who = n ? plural(n, 'host', 'hosts') + ', one at a time,'
        : 'up to ' + state.opts.max_hosts + ' hosts, one at a time,';
    } else {
      who = targetInput.value.trim() || 'the target';
    }
    let ports;
    if (state.ports === 'top') ports = 'the top 1000 TCP ports';
    else if (state.ports === 'all') ports = 'all 65535 TCP ports';
    else ports = customPorts() ? 'ports ' + customPorts() : 'a custom port list';
    const p = preset(state.base);
    const nuclei = state.sel.includes('vulns') ? 'nuclei on ' + (p ? p.vuln_mode : 'auto') : 'nuclei off';
    return 'Scan ' + who + ' on ' + ports + ' with ' + plural(state.sel.length, 'action', 'actions')
      + ', ' + nuclei + '.';
  }

  function render() {
    const isCode = state.mode === 'code';
    const isList = state.mode === 'list';

    modeButtons.forEach((btn, i) => {
      const on = btn.dataset.mode === state.mode;
      btn.classList.toggle('on', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
      if (on) modeInd.style.transform = 'translateX(' + i * 100 + '%)';
    });
    for (const group of root.querySelectorAll('[data-group]')) {
      group.hidden = group.dataset.group !== state.mode;
    }
    refs.targetHead.textContent = isCode ? 'Source code' : (isList ? 'Hosts' : 'Target');
    refs.targetHelp.textContent = isCode ? 'The code is read, never run.'
      : (isList ? 'One IP per line, up to ' + (state.opts ? state.opts.max_hosts : 8)
        + '. Each one is checked against the allowlist on its own.'
        : 'One IP address from your lab.');
    refs.portsPanel.hidden = isCode;
    refs.runPanel.hidden = isCode;

    portButtons.forEach((btn, i) => {
      const choice = btn.dataset.ports;
      btn.classList.toggle('on', choice === state.ports);
      btn.setAttribute('aria-pressed', choice === state.ports ? 'true' : 'false');
      btn.disabled = isList && choice === 'all';
      if (choice === state.ports) portInd.style.transform = 'translateX(' + i * 100 + '%)';
    });
    refs.customPorts.hidden = state.ports !== 'custom';
    refs.portsHelp.textContent = isList ? 'All 65535 is for one host only, so a list stays quick.'
      : 'All 65535 finds open ports fast first, then looks closely at those.';

    if (state.opts) {
      const shown = shownPreset();
      for (const p of state.opts.presets) {
        const card = presetCards[p.id];
        card.classList.toggle('on', shown === p.id);
        card.setAttribute('aria-pressed', shown === p.id ? 'true' : 'false');
        card.disabled = !presetAllowed(p);
      }
      refs.customNote.hidden = shown !== 'custom';
      refs.customNote.textContent = 'Custom, based on ' + presetName(state.base) + '.';
      for (const [id, { row, box }] of Object.entries(actionRows)) {
        const on = state.sel.includes(id);
        box.checked = on;
        row.classList.toggle('off', !on);
      }
    }

    const sentence = planSentence();
    if (sentence !== lastPlan) {
      refs.plan.textContent = sentence;
      if (!reducedMotion()) {
        refs.plan.classList.remove('flash');
        void refs.plan.offsetWidth; // restart the fade
        refs.plan.classList.add('flash');
      }
      lastPlan = sentence;
    }

    refs.startLabel.textContent = isCode ? 'Scan code'
      : (isList ? 'Scan ' + (hostLines().length ? plural(hostLines().length, 'host', 'hosts') : 'hosts')
        : 'Start scan');
    refs.startNote.hidden = !isList;
    refs.start.disabled = state.busy || isList || (!isCode && !state.opts);
    refs.start.setAttribute('aria-busy', state.busy ? 'true' : 'false');
    refs.spinner.hidden = !state.busy;
  }

  // ---- problems: field errors and alerts -------------------------------

  function fieldInput(field) {
    return { target: targetInput, ports: portsInput, path: pathInput }[field] || null;
  }

  function clearFieldError(field) {
    const box = root.querySelector('[data-error="' + field + '"]');
    if (box) {
      box.hidden = true;
      box.textContent = '';
    }
    const input = fieldInput(field);
    if (input) {
      input.classList.remove('bad');
      input.removeAttribute('aria-invalid');
    }
  }

  function clearProblems() {
    FIELDS.forEach(clearFieldError);
    refs.alert.replaceChildren();
  }

  /* Show the message under its field. False when that field is not on screen. */
  function showFieldError(field, message) {
    const box = root.querySelector('[data-error="' + field + '"]');
    if (!box || box.closest('[hidden]')) return false;
    box.textContent = message;
    box.hidden = false;
    const input = fieldInput(field);
    if (input) {
      input.classList.add('bad');
      input.setAttribute('aria-invalid', 'true');
      input.focus();
    } else {
      box.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
    }
    return true;
  }

  function showAlert(node) {
    refs.alert.replaceChildren(node);
    refs.alert.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
  }

  function showNotice(title, text, extra) {
    const { root: box, refs: r } = clone('tpl-notice');
    r.title.textContent = title;
    r.text.textContent = text || '';
    if (extra) r.extra.append(extra);
    showAlert(box);
  }

  function showRefused(target, networks) {
    // A new node each time, so the alert shakes once on every refusal.
    const { root: box, refs: r } = clone('tpl-refused');
    r.title.textContent = target + ' is not on the allowlist';
    const list = Array.isArray(networks) && networks.length ? networks : state.opts.allowlist;
    for (const net of list) r.nets.append(h('span', { class: 'net', text: net }));
    r.change.addEventListener('click', () => {
      refs.alert.replaceChildren();
      targetInput.focus();
      targetInput.select();
    });
    showAlert(box);
  }

  function handleFailure(data, body) {
    if (data.reason === 'refused') {
      showRefused(body.target, data.networks);
    } else if (data.reason === 'invalid') {
      if (!showFieldError(data.field, data.message)) {
        showNotice('This scan cannot start', data.message);
      }
    } else if (data.reason === 'busy') {
      const link = typeof data.job_id === 'string' && JOB_ID.test(data.job_id)
        ? h('a', { class: 'btn quiet', href: '#/job/' + data.job_id, text: 'Open the running scan' })
        : null;
      showNotice('A scan is already running', 'One scan runs at a time. Wait for it to finish or stop it first.', link);
    } else {
      showNotice('This scan cannot start', data.message || 'The server refused the request.');
    }
  }

  // ---- start -----------------------------------------------------------

  function requestBody() {
    if (state.mode === 'code') {
      return { kind: 'code', path: pathInput.value.trim(), explain: state.explain };
    }
    return {
      kind: 'recon',
      target: targetInput.value.trim(),
      preset: state.base,
      ports: portsValue(),
      actions: state.sel.slice(),
    };
  }

  function setBusy(busy) {
    state.busy = busy;
    render();
  }

  async function start() {
    if (state.busy || state.mode === 'list' || refs.start.disabled) return;
    clearProblems();
    const body = requestBody();
    setBusy(true);
    try {
      const check = await api.post('/api/check', body);
      if (!alive) return;
      if (check.status === 0) {
        showNotice('The ReconMind server is not answering', 'Check that python3 -m reconmind.web is still running.');
        return;
      }
      if (!check.ok || !check.data) {
        showNotice('The check did not run', (check.data && check.data.message) || 'The server answered with status ' + check.status + '.');
        return;
      }
      if (!check.data.ok) {
        handleFailure(check.data, body);
        return;
      }
      const started = await api.post('/api/scans', body);
      if (!alive) return;
      if (started.status === 201 && started.data && JOB_ID.test(String(started.data.job_id))) {
        location.hash = '#/job/' + started.data.job_id;
        return;
      }
      if (started.status === 0) {
        showNotice('The ReconMind server is not answering', 'Check that python3 -m reconmind.web is still running.');
      } else if (started.data && started.data.reason) {
        handleFailure(started.data, body);
      } else {
        showNotice('The scan did not start', 'The server answered with status ' + started.status + '.');
      }
    } finally {
      if (alive) setBusy(false);
    }
  }

  // ---- last scan -------------------------------------------------------

  function emptyLast(note) {
    const { root: card, refs: r } = clone('tpl-last-empty');
    if (note) r.sub.textContent = note;
    return card;
  }

  function event(time, text, extraClass) {
    return h('div', { class: 'evt' + (extraClass ? ' ' + extraClass : '') },
      time ? h('time', { text: time }) : null, text);
  }

  function severityRow(severity, count) {
    const n = Number(count) || 0;
    const value = h('span', { class: 'count' });
    countUp(value, n);
    return h('div', { class: 'frw' + (n ? '' : ' zero') },
      h('span', { class: 'sevword' }, heat(severity), SEVERITY_WORDS[severity] || severity),
      value);
  }

  function lastCard(entry) {
    const kind = entry.kind || 'recon';
    const findings = entry.findings && typeof entry.findings === 'object' ? entry.findings : {};
    const severities = kind === 'code' ? CODE_SEVERITIES : RECON_SEVERITIES;
    const total = severities.reduce((sum, s) => sum + (Number(findings[s]) || 0), 0)
      + (Number(findings.unknown) || 0);
    const started = parseTime(entry.started);
    const refused = entry.status === 'refused';
    const nodes = [];

    const { root: card, refs: r } = clone('tpl-last');
    const when = formatWhen(entry.finished) || formatWhen(entry.started);
    if (kind === 'code') {
      const files = Object.values(entry.languages || {}).reduce((a, b) => a + (Number(b) || 0), 0);
      if (started) nodes.push(event(clock(started), 'Read ' + plural(files, 'source file', 'source files')));
      r.when.textContent = (when ? when + ', ' : '') + 'report written';
      r.title.textContent = 'Code scan, ' + basename(entry.input);
      r.sub.textContent = plural(total, 'finding', 'findings')
        + (entry.ai_explanation ? ', explained with AI.' : '.');
    } else {
      const target = String(entry.target || 'unknown');
      if (started) {
        nodes.push(event(clock(started), refused ? 'Gate refused ' + target
          : 'Gate passed, ' + target + ' allowed'));
      }
      r.when.textContent = (when ? when + ', ' : '') + (refused ? 'refused' : 'report written');
      r.title.textContent = (PRESET_TITLES[entry.preset] || 'Scan') + ', ' + target;
      if (refused) {
        r.sub.textContent = 'Refused by the authorization gate. Nothing was sent.';
      } else {
        const ports = Number(entry.open_ports) || 0;
        r.sub.textContent = plural(ports, 'open port', 'open ports') + ', '
          + plural(total, 'finding', 'findings') + '.';
        if (started) nodes.push(event(null, plural(ports, 'open port', 'open ports') + ' mapped', 'e2'));
      }
    }
    if (!refused) {
      for (const s of severities) r.rows.append(severityRow(s, findings[s]));
    }
    nodes.push(card);
    return nodes;
  }

  async function loadLast() {
    const res = await api.get('/api/history');
    if (!alive) return;
    if (!res.ok || !res.data || !Array.isArray(res.data.entries)) {
      refs.last.replaceChildren(emptyLast('The report history could not be loaded.'));
      return;
    }
    const entry = res.data.entries.find((e) => e && typeof e === 'object');
    if (!entry) {
      refs.last.replaceChildren(emptyLast(res.data.warning || null));
      return;
    }
    refs.last.replaceChildren(...lastCard(entry));
    if (res.data.warning) refs.last.append(h('p', { class: 'tag', text: res.data.warning }));
  }

  // ---- wiring ----------------------------------------------------------

  modeButtons.forEach((btn) => btn.addEventListener('click', () => { setMode(btn.dataset.mode); render(); }));
  portButtons.forEach((btn) => btn.addEventListener('click', () => {
    pickPorts(btn.dataset.ports);
    render();
    if (state.ports === 'custom') portsInput.focus();
  }));
  explainInput.addEventListener('change', () => { state.explain = explainInput.checked; render(); });
  for (const [input, field] of [[targetInput, 'target'], [portsInput, 'ports'], [pathInput, 'path']]) {
    input.addEventListener('input', () => { clearFieldError(field); render(); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        start();
      }
    });
  }
  hostsInput.addEventListener('input', render);
  refs.start.addEventListener('click', start);

  render();
  loadLast();
  api.options().then((res) => {
    if (!alive) return;
    if (!res.ok || !res.data || !Array.isArray(res.data.presets)) {
      refs.allowed.textContent = 'the allowlist could not be loaded';
      if (res.status !== 0) showNotice('The scan options could not be loaded', 'Reload the page to try again.');
      return;
    }
    state.opts = res.data;
    refs.allowed.textContent = joinList(state.opts.allowlist);
    buildPresets();
    buildActions();
    applyPreset(state.opts.default_preset);
    render();
    targetInput.focus({ preventScroll: true });
  });

  return () => { alive = false; };
}
