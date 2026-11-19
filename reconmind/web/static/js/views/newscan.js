/*
 * New scan view (#/new), matching docs/design/screens/01_Main.html.
 *
 * Order: Target (or Hosts, or Source code), What to run, Ports, Checks,
 * AI analysis, then the plan sentence and Start.
 *
 * What to run has four cards: Quick, Standard, Full and Custom. Each card
 * shows a one line description and fact lines built from /api/options (the
 * ports, the checks and, when a preset tests web services deeply, a line that
 * says so), never hard coded here. While Quick, Standard or Full is picked,
 * the Ports and Checks panels are locked: read only, at full brightness, with
 * the picked values exactly as they look when unlocked, and a badge that says
 * which preset set them. Custom unlocks both and always starts from the
 * Standard preset's ports and checks.
 *
 * The request sends a preset with its own ports and actions, or for Custom
 * the preset "standard" with the user's ports and actions. "mode" is "ai"
 * when AI analysis is on, otherwise "standard". The engine calls the checks
 * "actions"; only the interface says "checks".
 *
 * AI analysis follows one rule for both scan types: it is on whenever an API
 * key is set up, and the user can turn it off for any scan.
 *
 * Host list scans up to max_hosts lab machines one after another with the same
 * settings (kind "hosts"). The server checks every host against the gate
 * before anything starts; the page then follows the list at #/hosts/<list id>.
 * The AI agent works on one target, so a list offers Off or AI analysis.
 * Starting an AI agent scan opens the MORVAIN-X0 tab, where its conversation
 * and the plan approvals live; every other scan opens Live run.
 *
 * The Last scan card links to that run's report (#/report/<run id>).
 *
 * The page never decides what is allowed: Start sends the request to
 * /api/check, which runs the authorization gate and the scan plan checks on
 * the server, and only then to /api/scans.
 */

import * as api from '../api.js';
import { markRunning } from '../live.js';
import {
  basename, clone, countUp, formatWhen, h, heat, isRunId, JOB_ID, joinList, parseTime, clock, plural,
  reducedMotion,
} from '../ui.js';

/* Short tool names and descriptions for each check. The job page uses the tool names too. */
export const ACTION_COPY = {
  surface: { tool: 'nmap', desc: 'Scans the target with nmap to find which TCP ports are open and which service and version runs on each. Always runs.' },
  exploits: { tool: 'searchsploit', desc: 'Searches Exploit-DB for public exploits that match each service and version nmap found, marks whether the version match is exact, and flags services that are risky just by being exposed.' },
  cves: { tool: 'NVD', desc: 'Looks up each service version in the NVD database and lists its known CVEs with CVSS scores. Flags any that CISA lists as actively exploited.' },
  web: { tool: 'httpx', desc: 'Connects to each web port and identifies the web server, frameworks and technologies in use, plus which security headers are missing.' },
  paths: { tool: 'ffuf', desc: 'Requests a list of common file and folder names on each web port to find pages that exist but are not linked, such as admin panels.' },
  vulns: { tool: 'nuclei', desc: 'Probes each web service for known vulnerabilities and misconfigurations. Safe checks only, no DoS or fuzzing.' },
  crypto: { tool: 'testssl.sh', desc: 'Tests every TLS port, including STARTTLS, for outdated protocol versions, weak ciphers and certificate problems.' },
  smb: { tool: 'enum4linux-ng', desc: 'Connects to SMB without a password and lists the shares, users, groups and domain details an anonymous user can see.' },
};

const CUSTOM = 'custom';
// Custom sends this preset with the user's ports and actions, and always starts from it.
const CUSTOM_BASE = 'standard';
const DEEP = 'deep';

const PRESET_COPY = {
  quick: { name: 'Quick', desc: 'Open ports and known exploits for each service. The fastest scan.' },
  standard: { name: 'Standard', desc: 'Everything in Quick, plus CVEs, web, TLS and SMB checks.' },
  full: { name: 'Full', desc: 'Everything in Standard on every port, with deeper web testing. One host at a time.' },
  custom: { name: 'Custom', desc: 'Choose the ports and checks yourself.' },
};
const PRESET_TITLES = { quick: 'Quick scan', standard: 'Standard scan', full: 'Full scan' };
const CUSTOM_TITLE = 'Custom scan';

const MODE_HELP = {
  host: 'Scan one lab machine over the network.',
  list: 'Scan several lab machines over the network, one at a time.',
  code: 'Find vulnerabilities in a file or folder of code on this computer. The code is read, never run.',
  malware: 'Future component: identify the malware family of a suspected file with a trained image classifier. Not part of this version.',
};

const AI_LEVEL_HELP = {
  off: 'Tools only. You pick the checks and no AI model is used.',
  ai: 'You pick the checks. They run exactly the same, then the AI reads the results and writes the summary, attack path and what to fix first.',
  agent: 'MORVAIN-X0 maps the surface, then proposes the next checks with its reasons. Nothing more runs until you approve each plan, and it stays on this one target inside the authorization gate. Your ports setting still applies. The agent picks the checks.',
};
const AI_LEVELS = ['off', 'ai', 'agent'];

const COPY = {
  badgeOpen: 'Your choice',
  aiNoteNetwork: 'Adds a written summary, the attack path and what to fix first. The checks run exactly the same either way, and every claim is checked against their results.',
  aiNoteCode: 'Explains why each finding is dangerous and how to fix it. Only the flagged lines are sent to the model, never whole files. The findings come from Semgrep and Bandit either way.',
  aiSentNetwork: ' The finished scan results are sent to the model. It reads them only and never runs a tool.',
  aiSentAgent: ' The scan results are sent to the model so it can plan. It can only pick from the 8 checks for this target, and you approve each plan.',
  aiNoKeyStart: 'No API key is set, so AI analysis is off. ',
  aiNoKeyLink: 'Add a key in System',
  aiNoKeyEnd: ' to turn it on.',
  aiUnknown: 'The AI setup could not be read, so AI analysis is off.',
  aiChecking: 'Checking whether an AI model is set up.',
  optionsFailed: 'The scan options could not be loaded. Reload to try again.',
  optionsLoading: 'The scan options are still loading.',
  needTarget: 'Enter a target IP address first.',
  needPorts: 'Enter the ports to scan first.',
  needPath: 'Enter the path of a file or folder first.',
  needHosts: 'Enter at least one lab host, one address per line.',
  tooManyHosts: 'A host list holds up to {m} hosts.',
  agentOneHost: 'The AI agent works on one target at a time. Choose Off or AI analysis for a host list.',
  serverDownTitle: 'The ReconMind server is not answering',
  serverDownText: 'Check that python3 -m reconmind.web is still running.',
  unreadable: 'The server sent an answer the page could not read. Try again.',
};
const PROVIDER_NAMES = {
  openrouter: 'OpenRouter', anthropic: 'Anthropic', huggingface: 'Hugging Face', ollama: 'Ollama',
};

const ALWAYS_ON = 'surface';
const MODES = ['host', 'list', 'code', 'malware'];
// Shown so the plan is visible, but it never starts anything (a future component).
const FUTURE_MODES = new Set(['malware']);
const PORT_CHOICES = ['top', 'all', 'custom'];
const FIELDS = ['target', 'ports', 'path', 'actions', 'hosts'];
const RECON_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const CODE_SEVERITIES = ['high', 'medium', 'low'];
const SEVERITY_WORDS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

/*
 * "Scan again" on a report fills New scan in: the target, the preset, and
 * for a rescan of some ports, Custom with those ports. Kept in memory only,
 * read once by the next New scan page.
 */
let prefill = null;
export function setPrefill(value) { prefill = value; }

export function mountNewScan(view) {
  const { root, refs } = clone('tpl-newscan');
  view.append(root);

  const targetInput = root.querySelector('#target');
  const hostsInput = root.querySelector('#hosts');
  const pathInput = root.querySelector('#path');
  const portsInput = root.querySelector('#ports');
  const aiInput = root.querySelector('#ai');
  const aiButtons = Array.from(root.querySelectorAll('[data-ai]'));
  const aiInd = root.querySelector('.seg-ai .ind');
  const modeButtons = Array.from(root.querySelectorAll('[data-mode]'));
  const portButtons = Array.from(root.querySelectorAll('[data-ports]'));
  const modeInd = root.querySelector('.seg-mode .ind');
  const portInd = root.querySelector('.seg-ports .ind');

  const state = {
    mode: 'host',
    picked: null,      // quick, standard, full or custom
    sel: [],           // ticked action ids, in /api/options order
    ports: 'top',      // top, all or custom (Specific ports)
    ai: false,         // AI analysis for a network scan
    aiLevel: 'off',    // network scans: off, ai (AI analysis) or agent (MORVAIN-X0)
    explain: false,    // AI analysis for a code scan
    aiAvailable: false,
    aiSetup: null,     // the "ai" object from /api/options, or null
    busy: false,
    opts: null,
    optsFailed: false,
  };
  const presetCards = {};
  const actionRows = {};
  let alive = true;
  let lastPlan = '';
  let lastAiInfo = null;

  // ---- options and helpers ---------------------------------------------

  const preset = (id) => (state.opts ? state.opts.presets.find((p) => p.id === id) || null : null);
  const actionIds = () => state.opts.actions.map((a) => a.id);
  const presetName = (id) => (PRESET_COPY[id] ? PRESET_COPY[id].name : String(id));
  const isCustom = () => state.picked === CUSTOM;
  // Ports and Checks are locked while a preset (not Custom) is picked.
  const locked = () => !isCustom();
  // Presets that scan every port are for one host at a time.
  const presetAllowed = (p) => !(state.mode === 'list' && p.ports === 'all');
  const visibleModes = () => modeButtons.filter((btn) => !btn.hidden);
  const aiOn = () => (state.mode === 'code' ? state.explain : state.ai);
  const aiLevel = () => (state.aiAvailable ? state.aiLevel : 'off');

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

  /* Custom always starts from the Standard preset's ports and checks. */
  function pickCustom() {
    if (isCustom()) return;
    applyPreset(CUSTOM_BASE);
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
    const btn = modeButtons.find((b) => b.dataset.mode === mode);
    if (!btn || btn.hidden) return;
    state.mode = mode;
    if (mode === 'list' && state.opts) {
      // Full and All 65535 are for one host only.
      const p = preset(state.picked);
      if (p && !presetAllowed(p)) {
        const fallback = listFallback();
        if (fallback) applyPreset(fallback);
      }
      if (state.ports === 'all') state.ports = 'top';
    }
    // The agent works on one target: a list uses AI analysis instead.
    if (mode === 'list' && state.aiLevel === 'agent') state.aiLevel = 'ai';
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

  function portsFact(p) {
    if (p.ports === 'top') return 'Ports: top 1000';
    if (p.ports === 'all') return 'Ports: all 65535';
    return 'Ports: ' + p.ports;
  }

  function checksFact(p) {
    const all = state.opts.actions;
    const names = all.filter((a) => p.actions.includes(a.id)).map((a) => a.name);
    if (names.length === all.length) return 'Checks: all ' + all.length;
    return 'Checks: ' + names.length + ' of ' + all.length + ' (' + names.join(', ') + ')';
  }

  function presetFacts(p) {
    if (!p) return ['Ports: your choice', 'Checks: your choice'];
    const facts = [portsFact(p), checksFact(p)];
    if (p.vuln_mode === DEEP) facts.push('Deeper web testing');
    return facts;
  }

  function presetCard(id, copy, p) {
    const card = h('button', {
      type: 'button',
      class: 'preset',
      'aria-pressed': 'false',
      onclick: () => { pick(id); render(); },
    },
    h('span', { class: 'dot', 'aria-hidden': 'true' }),
    h('span', { class: 'preset-text' },
      h('span', { class: 'preset-name', text: copy.name }),
      h('span', { class: 'preset-desc', text: copy.desc }),
      h('span', { class: 'preset-facts' },
        presetFacts(p).map((fact) => h('span', { class: 'preset-fact', text: fact })))));
    presetCards[id] = card;
    return card;
  }

  function buildPresets() {
    refs.presets.replaceChildren();
    for (const p of state.opts.presets) {
      refs.presets.append(presetCard(p.id, PRESET_COPY[p.id] || { name: p.id, desc: '' }, p));
    }
    refs.presets.append(presetCard(CUSTOM, PRESET_COPY.custom, null));
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
      const skip = h('span', { class: 'act-skip', hidden: true });
      const row = h('label', { class: 'act' + (always ? ' locked' : '') },
        box,
        h('span', { class: 'act-text' },
          h('span', {},
            h('span', { class: 'act-name', text: a.name }),
            h('span', { class: 'tag act-tool', text: copy.tool })),
          h('span', { class: 'act-desc', id: 'act-desc-' + a.id, text: copy.desc }),
          skip));
      actionRows[a.id] = { row, box, skip };
      refs.actions.append(row);
    }
  }

  function setupAi() {
    const ai = state.opts.ai && typeof state.opts.ai === 'object' ? state.opts.ai : null;
    state.aiSetup = ai;
    state.aiAvailable = !!(ai && ai.available === true);
    // One rule for both scan types: on whenever an API key is set up.
    state.ai = state.aiAvailable;
    state.aiLevel = state.aiAvailable ? 'ai' : 'off';
    state.explain = state.aiAvailable;
  }

  function optionsNotice() {
    const { root: box, refs: r } = clone('tpl-options-error');
    r.reload.addEventListener('click', () => location.reload());
    return box;
  }

  function optionsFailed() {
    state.optsFailed = true;
    state.aiSetup = null;
    state.aiAvailable = false;
    state.ai = false;
    state.aiLevel = 'off';
    state.explain = false;
    refs.allowed.textContent = 'the allowlist could not be loaded';
    refs.presets.replaceChildren(optionsNotice());
    refs.actions.replaceChildren(optionsNotice());
    render();
  }

  // ---- rendering -------------------------------------------------------

  function checksPhrase() {
    const total = state.opts.actions.length;
    const n = state.sel.length;
    return n === total ? 'all ' + total + ' checks' : n + ' of ' + total + ' checks';
  }

  function planSentence() {
    if (state.mode === 'malware') return 'Malware file analysis is a future component. Nothing runs in this version.';
    const level = state.mode === 'code' ? null : aiLevel();
    const ai = level === 'agent' ? ' AI agent MORVAIN-X0 proposes the checks and you approve each plan.'
      : (level === 'ai' || (level === null && aiOn()) ? ' AI analysis on.' : ' AI analysis off.');
    if (state.mode === 'code') {
      const path = pathInput.value.trim();
      const what = path ? basename(path) : 'the code';
      return 'Read ' + what + ' with Semgrep and Bandit.' + ai;
    }
    if (state.optsFailed) return COPY.optionsFailed;
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
    if (state.ports === 'top') ports = 'the top 1000 ports';
    else if (state.ports === 'all') ports = 'all 65535 ports';
    else ports = customPorts() ? 'ports ' + customPorts() : 'the ports you list';
    const p = isCustom() ? null : preset(state.picked);
    if (level === 'agent') {
      return 'MORVAIN-X0 maps ' + who + ' on ' + ports + ' with Surface Map and Exploit Hunt, '
        + 'then proposes the next checks. Nothing more runs until you approve each plan.';
    }
    const deeper = p && p.vuln_mode === DEEP && state.sel.includes('vulns')
      ? ', with deeper web testing' : '';
    return 'Scan ' + who + ' on ' + ports + ' with ' + checksPhrase() + deeper + '.' + ai;
  }

  /* Why Start cannot be pressed yet, or '' when it can. */
  function startBlocker() {
    if (FUTURE_MODES.has(state.mode)) return 'Malware file analysis is a future component. It is not part of this version.';
    if (state.optsFailed) return COPY.optionsFailed;
    if (state.mode === 'list') {
      const n = hostLines().length;
      if (!n) return COPY.needHosts;
      const max = state.opts ? state.opts.max_hosts : 8;
      if (n > max) return COPY.tooManyHosts.replace('{m}', max);
      if (aiLevel() === 'agent') return COPY.agentOneHost;
      if (!state.opts || !state.picked) return COPY.optionsLoading;
      if (state.ports === 'custom' && !customPorts()) return COPY.needPorts;
      return '';
    }
    if (state.mode === 'code') return pathInput.value.trim() ? '' : COPY.needPath;
    if (!state.opts || !state.picked) return COPY.optionsLoading;
    if (!targetInput.value.trim()) return COPY.needTarget;
    if (state.ports === 'custom' && !customPorts()) return COPY.needPorts;
    return '';
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
    text.textContent = open ? COPY.badgeOpen
      : 'Set by ' + presetName(state.picked) + '. Pick Custom to change.';
  }

  /* The provider line, or the no key line with its link to System. */
  function renderAiInfo() {
    const isCode = state.mode === 'code';
    const ai = state.aiSetup;
    const key = [state.optsFailed, !!state.opts, state.aiAvailable, isCode, aiLevel()].join('|');
    if (key === lastAiInfo) return;
    lastAiInfo = key;
    if (state.aiAvailable) {
      const provider = PROVIDER_NAMES[ai.provider] || String(ai.provider || 'the configured provider');
      refs.aiInfo.textContent = 'Uses ' + provider + (ai.model ? ', ' + String(ai.model) : '') + '.'
        + (isCode ? '' : (aiLevel() === 'agent' ? COPY.aiSentAgent : COPY.aiSentNetwork));
    } else if (ai) {
      refs.aiInfo.replaceChildren(
        COPY.aiNoKeyStart,
        h('a', { href: '#/system', text: COPY.aiNoKeyLink }),
        COPY.aiNoKeyEnd);
    } else if (state.optsFailed) {
      refs.aiInfo.textContent = COPY.aiUnknown;
    } else {
      refs.aiInfo.textContent = COPY.aiChecking;
    }
  }

  function render() {
    const isCode = state.mode === 'code';
    const isList = state.mode === 'list';
    const isFuture = FUTURE_MODES.has(state.mode);
    const isLocked = locked();

    // Mode switch: the visible buttons share the width.
    const shownModes = visibleModes();
    refs.modeSeg.classList.toggle('cols-2', shownModes.length === 2);
    refs.modeSeg.classList.toggle('cols-4', shownModes.length === 4);
    shownModes.forEach((btn, i) => {
      const on = btn.dataset.mode === state.mode;
      if (on) modeInd.style.transform = 'translateX(' + i * 100 + '%)';
    });
    modeButtons.forEach((btn) => {
      const on = btn.dataset.mode === state.mode;
      btn.classList.toggle('on', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    refs.modeHelp.textContent = MODE_HELP[state.mode];
    for (const group of root.querySelectorAll('[data-group]')) {
      group.hidden = group.dataset.group !== state.mode;
    }
    refs.targetHead.textContent = isFuture ? 'Malware file' : (isCode ? 'Source code' : (isList ? 'Hosts' : 'Target'));
    refs.targetHelp.textContent = isFuture ? 'A planned part of ReconMind, shown so you can see where it fits.'
      : isCode ? 'A file or folder on this computer.'
      : (isList ? 'One IP per line, up to ' + (state.opts ? state.opts.max_hosts : 8)
        + '. Each one is checked against the allowlist on its own.'
        : 'One IP address from your lab.');
    refs.runPanel.hidden = isCode || isFuture;
    refs.portsPanel.hidden = isCode || isFuture;
    refs.actionsPanel.hidden = isCode || isFuture;
    refs.aiPanel.hidden = isFuture;

    // Ports: read only while a preset is picked.
    refs.portsPanel.classList.toggle('locked', isLocked);
    renderBadge(refs.portsBadge, refs.portsBadgeText);
    refs.portsHelp.hidden = isLocked;
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

    // Checks: read only while a preset is picked; Surface Map always on.
    refs.actionsPanel.classList.toggle('locked', isLocked);
    renderBadge(refs.actionsBadge, refs.actionsBadgeText);
    refs.actionsHelp.hidden = isLocked || !state.opts;

    if (state.opts) {
      for (const [id, card] of Object.entries(presetCards)) {
        const on = state.picked === id;
        card.classList.toggle('on', on);
        card.setAttribute('aria-pressed', on ? 'true' : 'false');
        const p = preset(id);
        card.disabled = !!p && !presetAllowed(p);
      }
      const notIn = 'Not in ' + presetName(state.picked);
      for (const [id, { row, box, skip }] of Object.entries(actionRows)) {
        const on = state.sel.includes(id);
        box.checked = on;
        box.disabled = isLocked || id === ALWAYS_ON;
        row.classList.toggle('off', !on);
        skip.hidden = !(isLocked && !on);
        skip.textContent = notIn;
      }
    }

    // AI analysis: one switch, one rule for both scan types; off and disabled without a key.
    aiInput.disabled = !state.aiAvailable;
    aiInput.checked = state.aiAvailable && aiOn();
    refs.aiRow.classList.toggle('disabled', !state.aiAvailable);
    // Network scans: one control with three settings. Code scans keep the switch.
    refs.aiSeg.hidden = isCode;
    refs.aiLevelHelp.hidden = isCode;
    refs.aiRow.hidden = !isCode;
    const level = aiLevel();
    aiButtons.forEach((btn, i) => {
      const on = btn.dataset.ai === level;
      btn.classList.toggle('on', on);
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.disabled = (btn.dataset.ai !== 'off' && !state.aiAvailable)
        || (isList && btn.dataset.ai === 'agent');
      if (on) aiInd.style.transform = 'translateX(' + i * 100 + '%)';
    });
    refs.aiLevelHelp.textContent = AI_LEVEL_HELP[level];
    refs.aiNote.textContent = isCode ? COPY.aiNoteCode : COPY.aiNoteNetwork;
    renderAiInfo();

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

    refs.startLabel.textContent = isFuture ? 'Future component' : isCode ? 'Scan code'
      : (isList ? 'Scan ' + (hostLines().length ? plural(hostLines().length, 'host', 'hosts') : 'hosts')
        : 'Start scan');
    refs.startNote.hidden = !isList;
    const blocker = startBlocker();
    refs.start.disabled = state.busy || !!blocker;
    if (blocker && !state.busy) refs.start.setAttribute('title', blocker);
    else refs.start.removeAttribute('title');
    refs.start.setAttribute('aria-busy', state.busy ? 'true' : 'false');
    refs.spinner.hidden = !state.busy;
  }

  // ---- problems: field errors and alerts -------------------------------

  function fieldInput(field) {
    return { target: targetInput, ports: portsInput, path: pathInput, hosts: hostsInput }[field] || null;
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
    const list = Array.isArray(networks) && networks.length ? networks
      : (state.opts ? state.opts.allowlist : []);
    for (const net of list) r.nets.append(h('span', { class: 'net', text: String(net) }));
    r.change.addEventListener('click', () => {
      refs.alert.replaceChildren();
      targetInput.focus();
      targetInput.select();
    });
    showAlert(box);
  }

  function handleFailure(data, body) {
    const message = typeof data.message === 'string' && data.message ? data.message : null;
    if (data.reason === 'refused' && body.kind === 'hosts') {
      showNotice('A host is not on the allowlist', message || 'The gate refused a host.');
      hostsInput.focus();
    } else if (data.reason === 'refused') {
      showRefused(String(body.target || 'The target'), data.networks);
    } else if (data.reason === 'invalid') {
      const field = typeof data.field === 'string' ? data.field : '';
      if (!showFieldError(field, message || 'This value is not valid.')) {
        showNotice('This scan cannot start', message || 'The server refused the request.');
      }
    } else if (data.reason === 'busy') {
      const link = typeof data.job_id === 'string' && JOB_ID.test(data.job_id)
        ? h('a', { class: 'btn quiet', href: '#/job/' + data.job_id, text: 'Open the running scan' })
        : null;
      markRunning();
      showNotice('A scan is already running', 'One scan runs at a time. Wait for it to finish or stop it first.', link);
    } else {
      showNotice('This scan cannot start', message || 'The server refused the request.');
    }
  }

  // ---- start -----------------------------------------------------------

  function requestBody() {
    if (state.mode === 'code') {
      return { kind: 'code', path: pathInput.value.trim(), explain: state.aiAvailable && state.explain };
    }
    const level = aiLevel();
    const mode = level === 'agent' ? 'agent' : (level === 'ai' ? 'ai' : 'standard');
    const who = state.mode === 'list' ? { kind: 'hosts', targets: hostLines() }
      : { kind: 'recon', target: targetInput.value.trim() };
    if (isCustom()) {
      return Object.assign(who, {
        preset: CUSTOM_BASE, ports: portsValue(), actions: state.sel.slice(), mode,
      });
    }
    // A preset always sends its own ports and actions, straight from /api/options.
    const p = preset(state.picked);
    return Object.assign(who, { preset: p.id, ports: p.ports, actions: p.actions.slice(), mode });
  }

  function setBusy(busy) {
    state.busy = busy;
    render();
  }

  const isAnswer = (data) => !!data && typeof data === 'object' && !Array.isArray(data);

  /* A calm notice for a request that did not get a usable answer. */
  function requestProblem(res, title) {
    if (res.status === 0) showNotice(COPY.serverDownTitle, COPY.serverDownText);
    else if (res.ok) showNotice(title, COPY.unreadable);
    else showNotice(title, 'The server answered with status ' + res.status + '. Try again.');
  }

  async function start() {
    if (state.busy || refs.start.disabled || startBlocker()) return;
    clearProblems();
    setBusy(true);
    try {
      const body = requestBody();
      const check = await api.post('/api/check', body);
      if (!alive) return;
      if (!isAnswer(check.data) || (!check.ok && !check.data.reason)) {
        requestProblem(check, 'The check did not run');
        return;
      }
      if (check.data.ok !== true) {
        handleFailure(check.data, body);
        return;
      }
      const started = await api.post('/api/scans', body);
      if (!alive) return;
      if (started.status === 201 && isAnswer(started.data) && /^[0-9a-f]{10}$/.test(String(started.data.list_id))) {
        markRunning();
        location.hash = '#/hosts/' + started.data.list_id;
        return;
      }
      if (started.status === 201 && isAnswer(started.data) && JOB_ID.test(String(started.data.job_id))) {
        markRunning();
        // The agent's conversation and approvals live on its own tab.
        location.hash = body.mode === 'agent' ? '#/agent' : '#/job/' + started.data.job_id;
        return;
      }
      if (isAnswer(started.data) && started.data.reason) {
        handleFailure(started.data, body);
      } else {
        requestProblem(started, 'The scan did not start');
      }
    } catch (err) {
      if (alive) showNotice('The scan did not start', 'Something went wrong in the page. Reload and try again.');
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

  /* "Quick scan", or "Custom scan" when the run's ports or checks were changed. */
  function scanTitle(entry) {
    if (entry.customized === true) return CUSTOM_TITLE;
    return PRESET_TITLES[entry.preset] || 'Scan';
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
      const languages = entry.languages && typeof entry.languages === 'object' ? entry.languages : {};
      const files = Object.values(languages).reduce((a, b) => a + (Number(b) || 0), 0);
      if (started) nodes.push(event(clock(started), 'Read ' + plural(files, 'source file', 'source files')));
      r.when.textContent = (when ? when + ', ' : '') + 'report written';
      r.title.textContent = 'Code scan, ' + basename(entry.input);
      r.sub.textContent = plural(total, 'finding', 'findings')
        + (entry.ai_explanation ? ', with AI analysis.' : '.');
    } else {
      const target = String(entry.target || 'unknown');
      if (started) {
        nodes.push(event(clock(started), refused ? 'Gate refused ' + target
          : 'Gate passed, ' + target + ' allowed'));
      }
      r.when.textContent = (when ? when + ', ' : '') + (refused ? 'refused' : 'report written');
      r.title.textContent = scanTitle(entry) + ', ' + target;
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
    if (isRunId(entry.run_id)) {
      card.append(h('a', {
        class: 'ev-open', href: '#/report/' + encodeURIComponent(entry.run_id), text: 'Open report',
      }));
    }
    nodes.push(card);
    return nodes;
  }

  async function loadLast() {
    let res;
    try {
      res = await api.get('/api/history');
    } catch (err) {
      res = { ok: false, status: 0, data: null };
    }
    if (!alive) return;
    if (res.status === 0) {
      refs.last.replaceChildren(emptyLast('The report history could not be loaded. The ReconMind server is not answering.'));
      return;
    }
    if (!res.ok || !isAnswer(res.data) || !Array.isArray(res.data.entries)) {
      refs.last.replaceChildren(emptyLast('The report history could not be loaded.'));
      return;
    }
    const warning = typeof res.data.warning === 'string' ? res.data.warning : null;
    const entry = res.data.entries.find((e) => isAnswer(e));
    if (!entry) {
      refs.last.replaceChildren(emptyLast(warning));
      return;
    }
    try {
      refs.last.replaceChildren(...lastCard(entry));
    } catch (err) {
      refs.last.replaceChildren(emptyLast('The last scan could not be shown.'));
      return;
    }
    if (warning) refs.last.append(h('p', { class: 'tag', text: warning }));
  }

  // ---- wiring ----------------------------------------------------------

  modeButtons.forEach((btn) => btn.addEventListener('click', () => { setMode(btn.dataset.mode); render(); }));
  portButtons.forEach((btn) => btn.addEventListener('click', () => {
    pickPorts(btn.dataset.ports);
    render();
    if (state.ports === 'custom' && !portsInput.disabled) portsInput.focus();
  }));
  aiButtons.forEach((btn) => btn.addEventListener('click', () => {
    if (!AI_LEVELS.includes(btn.dataset.ai) || btn.disabled) return;
    state.aiLevel = btn.dataset.ai;
    state.ai = state.aiLevel !== 'off';
    render();
  }));
  aiInput.addEventListener('change', () => {
    const on = state.aiAvailable && aiInput.checked;
    if (state.mode === 'code') state.explain = on;
    else { state.ai = on; state.aiLevel = on ? 'ai' : 'off'; }
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
  hostsInput.addEventListener('input', () => { clearFieldError('hosts'); render(); });
  refs.start.addEventListener('click', start);

  render();
  loadLast();
  api.options().then((res) => {
    if (!alive) return;
    if (!res.ok) {
      optionsFailed();
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
    const wanted = prefill;
    prefill = null;
    if (wanted && typeof wanted.target === 'string') {
      targetInput.value = wanted.target;
      if (wanted.preset === CUSTOM) {
        pickCustom();
        if (wanted.ports) { state.ports = 'custom'; portsInput.value = wanted.ports; }
      } else if (preset(wanted.preset)) {
        applyPreset(wanted.preset);
      }
    }
    render();
    targetInput.focus({ preventScroll: true });
  }).catch(() => {
    if (alive) optionsFailed();
  });

  return () => { alive = false; };
}
