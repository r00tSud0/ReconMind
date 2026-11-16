/*
 * New scan view (#/new), matching docs/design/screens/01_Main.html.
 *
 * Order: Target (or Hosts, or Source code), What to run, Ports, Actions,
 * AI analysis, then the plan sentence and Start.
 *
 * What to run has four cards: Quick, Standard, Full report and Custom. The
 * actions, ports and nuclei mode of Quick, Standard and Full report come
 * from /api/options, never from this file. While one of those is picked, the
 * Ports and Actions panels are locked (DESIGN 5.13a): every control is
 * disabled, the picked values stay readable and a badge says which preset
 * set them. Custom unlocks both, starting from the last preset's values.
 *
 * The request sends a preset with its own ports and actions, or for Custom
 * the preset "standard" with the user's ports and actions, so nuclei stays on
 * auto. "mode" is "ai" when the AI switch is on, otherwise "standard".
 *
 * The page never decides what is allowed: Start sends the request to
 * /api/check, which runs the authorization gate and the scan plan checks on
 * the server, and only then to /api/scans.
 */

import * as api from '../api.js';
import { markRunning } from '../live.js';
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

const CUSTOM = 'custom';
// Custom sends this preset with the user's ports and actions, so nuclei stays on auto.
const CUSTOM_BASE = 'standard';

/*
 * Copy for the cards, the locked and open help, and the AI note (DESIGN
 * section 7, "New scan order and rules"). Fixed panel help lives in
 * index.html.
 */
const PRESET_COPY = {
  quick: { name: 'Quick', desc: 'Scans the top 1000 ports, then checks each service for public exploits and known CVEs.' },
  standard: { name: 'Standard', desc: 'Scans the top 1000 ports and runs all 8 actions. Nuclei only runs templates that match the technology it detects.' },
  full: { name: 'Full report', desc: 'Scans all 65535 ports and runs all 8 actions with every safe nuclei template. One host at a time.' },
  custom: { name: 'Custom', desc: 'You choose the ports and the actions. Starts from what the last preset had.' },
};
const COPY = {
  portsLocked: 'Pick Custom above to change the ports.',
  portsOpen: 'All 65535 finds open ports fast first, then looks closely at those.',
  portsOpenList: 'All 65535 is for one host only, so a list stays quick.',
  actionsLocked: 'This is exactly what will run. Pick Custom above to change it.',
  actionsOpen: 'Tick what to look for. Each action only runs on the ports it fits.',
  badgeOpen: 'Yours to choose',
  aiSent: 'The finished scan results are sent to the model. It reads them only and never runs a tool.',
  aiNoKeyStart: 'No API key is set, so scans make a Standard report. ',
  aiNoKeyLink: 'Add a key in System',
  aiNoKeyEnd: ' to turn this on.',
  aiUnknown: 'The AI setup could not be read, so scans make a Standard report.',
  reportAi: 'You get an AI enhanced report.',
  reportStandard: 'You get a Standard report.',
};
const PROVIDER_NAMES = {
  openrouter: 'OpenRouter', anthropic: 'Anthropic', huggingface: 'Hugging Face', ollama: 'Ollama',
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
  const aiInput = root.querySelector('#ai');
  const modeButtons = Array.from(root.querySelectorAll('[data-mode]'));
  const portButtons = Array.from(root.querySelectorAll('[data-ports]'));
  const modeInd = root.querySelector('.seg-mode .ind');
  const portInd = root.querySelector('.seg-ports .ind');

  const state = {
    mode: 'host',
    picked: null,    // quick, standard, full or custom
    last: null,      // the last preset picked (never custom)
    sel: [],         // ticked action ids, in /api/options order
    ports: 'top',    // top, all or custom
    explain: false,
    ai: false,
    aiAvailable: false,
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
  const isCustom = () => state.picked === CUSTOM;
  // Ports and Actions are locked while a preset (not Custom) is picked.
  const locked = () => !isCustom();
  // Presets that scan every port are for one host at a time.
  const presetAllowed = (p) => !(state.mode === 'list' && p.ports === 'all');

  // "22, 80" and "22,80" mean the same; the server still checks the spec itself.
  function customPorts() {
    return portsInput.value.replace(/\s+/g, '');
  }

  function portsValue() {
    return state.ports === 'custom' ? customPorts() : state.ports;
  }

  function hostLines() {
    return hostsInput.value.split('\n').map((s) => s.trim()).filter(Boolean);
  }

  /* The preset a list falls back to when the picked one scans every port. */
  function listFallback() {
    const def = preset(state.opts.default_preset);
    if (def && presetAllowed(def)) return def.id;
    const any = state.opts.presets.find(presetAllowed);
    return any ? any.id : null;
  }

  // ---- state changes ---------------------------------------------------

  function applyPreset(id) {
    const p = preset(id);
    if (!p || !presetAllowed(p)) return;
    state.picked = p.id;
    state.last = p.id;
    state.sel = actionIds().filter((a) => p.actions.includes(a));
    if (p.ports === 'top' || p.ports === 'all') {
      state.ports = p.ports;
    } else {
      state.ports = 'custom';
      portsInput.value = p.ports;
    }
    clearFieldError('ports');
    clearFieldError('actions');
  }

  /* Custom starts from the ports and actions the last picked preset had. */
  function pickCustom() {
    if (isCustom()) return;
    if (state.last) applyPreset(state.last);
    state.picked = CUSTOM;
    if (state.mode === 'list' && state.ports === 'all') state.ports = 'top';
  }

  function pick(id) {
    if (!state.opts) return;
    if (id === CUSTOM) pickCustom();
    else applyPreset(id);
  }

  function setMode(mode) {
    if (!MODES.includes(mode) || mode === state.mode) return;
    state.mode = mode;
    if (mode === 'list' && state.opts) {
      // Full report and All 65535 are for one host only.
      const p = preset(state.picked);
      if (p && !presetAllowed(p)) {
        const fallback = listFallback();
        if (fallback) applyPreset(fallback);
      }
      if (state.ports === 'all') state.ports = 'top';
    }
    clearProblems();
  }

  function toggleAction(id, on) {
    if (id === ALWAYS_ON || locked()) return;
    const chosen = new Set(state.sel);
    if (on) chosen.add(id);
    else chosen.delete(id);
    chosen.add(ALWAYS_ON);
    state.sel = actionIds().filter((a) => chosen.has(a));
    clearFieldError('actions');
  }

  function pickPorts(choice) {
    if (!PORT_CHOICES.includes(choice) || locked()) return;
    if (state.mode === 'list' && choice === 'all') return;
    state.ports = choice;
    clearFieldError('ports');
  }

  // ---- building the lists from /api/options ----------------------------

  function presetCard(id, copy) {
    const card = h('button', {
      type: 'button',
      class: 'preset',
      'aria-pressed': 'false',
      onclick: () => { pick(id); render(); },
    },
    h('span', { class: 'dot', 'aria-hidden': 'true' }),
    h('span', { class: 'preset-text' },
      h('span', { class: 'preset-name', text: copy.name }),
      h('span', { class: 'preset-desc', text: copy.desc })));
    presetCards[id] = card;
    return card;
  }

  function buildPresets() {
    refs.presets.replaceChildren();
    for (const p of state.opts.presets) {
      refs.presets.append(presetCard(p.id, PRESET_COPY[p.id] || { name: p.id, desc: '' }));
    }
    refs.presets.append(presetCard(CUSTOM, PRESET_COPY.custom));
  }

  function buildActions() {
    refs.actions.replaceChildren();
    for (const a of state.opts.actions) {
      const copy = ACTION_COPY[a.id] || { tool: a.tools.join(', '), desc: '' };
      const always = a.id === ALWAYS_ON;
      const box = h('input', {
        type: 'checkbox',
        class: 'ck',
        disabled: true,
        'aria-describedby': 'act-desc-' + a.id,
        onchange: (event) => { toggleAction(a.id, event.target.checked); render(); },
      });
      const row = h('label', { class: 'act' + (always ? ' locked' : '') },
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

  function setupAi() {
    const ai = state.opts.ai && typeof state.opts.ai === 'object' ? state.opts.ai : null;
    state.aiAvailable = !!(ai && ai.available === true);
    state.ai = state.aiAvailable;
    aiInput.checked = state.ai;
    if (state.aiAvailable) {
      const provider = PROVIDER_NAMES[ai.provider] || String(ai.provider || 'the configured provider');
      refs.aiInfo.textContent = 'Uses ' + provider + (ai.model ? ', ' + String(ai.model) : '')
        + '. ' + COPY.aiSent;
    } else if (ai) {
      refs.aiInfo.replaceChildren(
        COPY.aiNoKeyStart,
        h('a', { href: '#/system', text: COPY.aiNoKeyLink }),
        COPY.aiNoKeyEnd);
    } else {
      refs.aiInfo.textContent = COPY.aiUnknown;
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
    const p = preset(isCustom() ? CUSTOM_BASE : state.picked);
    const nuclei = state.sel.includes('vulns') ? 'nuclei on ' + (p ? p.vuln_mode : 'auto') : 'nuclei off';
    return 'Scan ' + who + ' on ' + ports + ' with ' + plural(state.sel.length, 'action', 'actions')
      + ', ' + nuclei + '. ' + (state.ai ? COPY.reportAi : COPY.reportStandard);
  }

  function renderBadge(badge, text) {
    const open = isCustom();
    badge.hidden = !state.opts;
    if (badge.classList.contains('open') !== open) {
      badge.classList.toggle('open', open);
      // Pop again on every switch between locked and open.
      badge.classList.remove('pop');
      void badge.offsetWidth;
      badge.classList.add('pop');
    }
    text.textContent = open ? COPY.badgeOpen : 'Set by ' + presetName(state.picked);
  }

  function render() {
    const isCode = state.mode === 'code';
    const isList = state.mode === 'list';
    const isLocked = locked();

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
    refs.runPanel.hidden = isCode;
    refs.portsPanel.hidden = isCode;
    refs.actionsPanel.hidden = isCode;
    refs.aiPanel.hidden = isCode;

    // Ports: locked while a preset is picked.
    refs.portsPanel.classList.toggle('locked', isLocked);
    renderBadge(refs.portsBadge, refs.portsBadgeText);
    portButtons.forEach((btn, i) => {
      const choice = btn.dataset.ports;
      btn.classList.toggle('on', choice === state.ports);
      btn.setAttribute('aria-pressed', choice === state.ports ? 'true' : 'false');
      const never = isList && choice === 'all';
      btn.classList.toggle('never', never);
      btn.disabled = isLocked || never;
      if (choice === state.ports) portInd.style.transform = 'translateX(' + i * 100 + '%)';
    });
    refs.customPorts.hidden = state.ports !== 'custom';
    portsInput.disabled = isLocked;
    refs.portsHelp.textContent = isLocked ? COPY.portsLocked
      : (isList ? COPY.portsOpenList : COPY.portsOpen);

    // Actions: locked while a preset is picked; Surface Map always on.
    refs.actionsPanel.classList.toggle('locked', isLocked);
    renderBadge(refs.actionsBadge, refs.actionsBadgeText);
    refs.actionsHelp.textContent = isLocked ? COPY.actionsLocked : COPY.actionsOpen;

    if (state.opts) {
      for (const [id, card] of Object.entries(presetCards)) {
        const on = state.picked === id;
        card.classList.toggle('on', on);
        card.setAttribute('aria-pressed', on ? 'true' : 'false');
        const p = preset(id);
        card.disabled = !!p && !presetAllowed(p);
      }
      for (const [id, { row, box }] of Object.entries(actionRows)) {
        const on = state.sel.includes(id);
        box.checked = on;
        box.disabled = isLocked || id === ALWAYS_ON;
        row.classList.toggle('off', !on);
      }
    }

    // AI analysis: off and disabled when no model is set up.
    aiInput.disabled = !state.aiAvailable;
    aiInput.checked = state.ai;
    refs.aiRow.classList.toggle('disabled', !state.aiAvailable);

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
      if (!input.disabled) input.focus();
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
      markRunning();
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
    const mode = state.ai ? 'ai' : 'standard';
    const target = targetInput.value.trim();
    if (isCustom()) {
      return {
        kind: 'recon', target, preset: CUSTOM_BASE, ports: portsValue(),
        actions: state.sel.slice(), mode,
      };
    }
    // A preset always sends its own ports and actions, straight from /api/options.
    const p = preset(state.picked);
    return {
      kind: 'recon', target, preset: p.id, ports: p.ports, actions: p.actions.slice(), mode,
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
        markRunning();
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
    if (state.ports === 'custom' && !portsInput.disabled) portsInput.focus();
  }));
  explainInput.addEventListener('change', () => { state.explain = explainInput.checked; render(); });
  aiInput.addEventListener('change', () => {
    state.ai = state.aiAvailable && aiInput.checked;
    render();
  });
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
      refs.aiInfo.textContent = COPY.aiUnknown;
      if (res.status !== 0) showNotice('The scan options could not be loaded', 'Reload the page to try again.');
      return;
    }
    state.opts = res.data;
    refs.allowed.textContent = joinList(state.opts.allowlist);
    buildPresets();
    buildActions();
    setupAi();
    applyPreset(state.opts.default_preset);
    // Host list picked before the options arrived: never a preset that scans every port.
    if (!state.picked) {
      const fallback = listFallback();
      if (fallback) applyPreset(fallback);
    }
    render();
    targetInput.focus({ preventScroll: true });
  });

  return () => { alive = false; };
}
