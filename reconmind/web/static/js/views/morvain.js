/*
 * MORVAIN-X0 (#/agent): the agent's own tab, after artboard 11.
 *
 * With no agent session, the character waits in its Ready state next to a
 * short start form (one lab target and the ports). With an agent session
 * running or just finished, the page shows the session: the character, the
 * conversation with its plan cards, and the live progress panel. The scan
 * itself is a normal job (mode "agent"): Live run shows its tool steps and
 * points back here. The conversation and the approvals live only on this tab.
 * Agent scans start only here: you give the target and the ports, MORVAIN-X0
 * chooses from all 8 checks, reports what it found and its plan, and you
 * approve, redirect or stop. You can ask it questions at every plan, and
 * keep asking about the saved report once the session is over.
 *
 * Nothing from the server is parsed as HTML: every node is built with h().
 */
import * as api from '../api.js';
import { h } from '../ui.js';
import { checkLive, markRunning } from '../live.js';
import { createAgentPanel } from './agent.js';

const isObject = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const AGENT_LABEL = 'Agent scan, ';
const JOB_ID = /^[0-9a-f]{12}$/;

function stat(label, value, hot) {
  return h('div', { class: 'agent-stat' },
    h('span', { text: label }),
    h('span', { class: 'agent-pill' + (hot ? ' hot' : ''), text: String(value) }));
}

export function mountMorvain(view) {
  let alive = true;
  let timer = null;
  let job = null;
  let panel = null;
  let since = 0;
  let wasRunning = false;
  const progress = { gate: false, ports: null, exploits: null, done: 0, failed: 0, plan: 0 };

  const root = h('main', { class: 'page page-wide morvain-page' });
  const grid = h('div', { class: 'morvain-grid' });
  const side = h('aside', { class: 'glass agent-progress', 'aria-label': 'Live progress' });
  root.append(grid);
  view.append(root);

  // ---- the start form (no session) -------------------------------------
  function startForm(options) {
    const ai = isObject(options && options.ai) ? options.ai : {};
    const allowed = Array.isArray(options && options.allowlist) ? options.allowlist.map(String) : [];
    const target = h('input', { id: 'agent-target', class: 'field field-big', type: 'text',
      autocomplete: 'off', spellcheck: 'false', inputmode: 'decimal', placeholder: '10.10.1.20' });
    let ports = 'top';
    const CHOICES = [['top', 'Top 1000'], ['all', 'All 65535'], ['custom', 'Specific ports']];
    const portsField = h('input', { id: 'agent-ports-field', class: 'field field-mono', type: 'text',
      autocomplete: 'off', spellcheck: 'false', placeholder: '21,22,80,443,8000-8100',
      'aria-label': 'Specific ports' });
    const portsBox = h('div', { class: 'agent-ports-custom', hidden: true }, portsField,
      h('p', { class: 'tag', text: 'Numbers and ranges, like 21,22,80 or 8000-8100. MORVAIN-X0 scans only these.' }));
    const portButtons = CHOICES.map(([id, text]) => {
      const b = h('button', { type: 'button', text, 'aria-pressed': id === ports ? 'true' : 'false',
        class: id === ports ? 'on' : '' });
      b.addEventListener('click', () => {
        ports = id;
        portButtons.forEach((x, i) => {
          const on = CHOICES[i][0] === ports;
          x.className = on ? 'on' : '';
          x.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        ind.style.transform = 'translateX(' + CHOICES.findIndex((c) => c[0] === ports) * 100 + '%)';
        portsBox.hidden = ports !== 'custom';
        if (ports === 'custom') portsField.focus();
      });
      return b;
    });
    const ind = h('span', { class: 'ind', 'aria-hidden': 'true' });
    const start = h('button', { type: 'button', class: 'btn primary', text: 'Start agent scan',
      disabled: !ai.available });
    const note = h('p', { class: 'help agent-start-note', role: 'status', 'aria-live': 'polite' });
    if (!ai.available) {
      note.replaceChildren('MORVAIN-X0 needs an AI model. Set a provider and key on ',
        h('a', { href: '#/system', text: 'System' }), ', then come back.');
    } else {
      note.textContent = 'It maps the surface with Surface Map and Exploit Hunt, then proposes '
        + 'the next checks. Nothing more runs until you approve each plan.';
    }
    async function go() {
      const value = target.value.trim();
      if (!value) {
        note.textContent = 'Enter the IPv4 address of one lab target.';
        target.focus();
        return;
      }
      const spec = portsField.value.replace(/\s+/g, '');
      if (ports === 'custom' && !spec) {
        note.textContent = 'Type the ports to scan, like 21,22,80.';
        portsField.focus();
        return;
      }
      start.disabled = true;
      note.textContent = 'Checking the target against the authorization gate.';
      const res = await api.post('/api/scans', { kind: 'recon', target: value, preset: 'standard',
        ports: ports === 'custom' ? spec : ports, mode: 'agent' });
      if (!alive) return;
      if (res.ok && isObject(res.data) && JOB_ID.test(String(res.data.job_id))) {
        job = { id: res.data.job_id, status: 'running', label: AGENT_LABEL + value };
        markRunning();
        showSession();
        return;
      }
      start.disabled = false;
      const d = isObject(res.data) ? res.data : {};
      note.textContent = d.message ? String(d.message) : 'The agent scan could not start.';
      if (d.reason === 'busy' && JOB_ID.test(String(d.job_id || ''))) {
        note.append(' ', h('a', { href: '#/job/' + d.job_id, text: 'Open the running scan' }));
      }
    }
    start.addEventListener('click', go);
    target.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    portsField.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    return h('div', { class: 'agent-start' },
      h('div', { class: 'agent-msg' },
        h('span', { class: 'agent-av x', text: 'X0' }),
        h('div', { class: 'agent-bubble x' },
          h('div', { class: 'agent-who', text: 'MORVAIN-X0' }),
          h('span', { text: 'Give me one lab target. I will map what is exposed, then propose '
            + 'what to check next and why. You approve every plan, and the authorization gate '
            + 'decides what I may touch.' }))),
      h('div', { class: 'group' },
        h('label', { class: 'label', for: 'agent-target', text: 'Lab target (IPv4)' }), target,
        h('p', { class: 'tag', text: allowed.length ? 'Allowed: ' + allowed.join(', ') : '' })),
      h('div', { class: 'group' },
        h('span', { class: 'label', text: 'Ports' }),
        h('div', { class: 'seg agent-ports', role: 'group', 'aria-label': 'Ports' },
          ind, ...portButtons), portsBox),
      h('div', { class: 'agent-start-actions' }, start),
      note);
  }

  async function showIdle() {
    panel = createAgentPanel(null);
    panel.setJob('ready');
    panel.setTitle('Start an agent scan');
    const res = await api.options();
    if (!alive) return;
    panel.setIntro(startForm(res.ok ? res.data : null));
    panel.render();
    grid.replaceChildren(panel.el);
    setTimeout(() => { const t = root.querySelector('#agent-target'); if (t) t.focus(); }, 0);
  }

  // ---- the session -----------------------------------------------------
  function renderProgress() {
    const running = job && job.status === 'running';
    side.replaceChildren(
      h('h2', { class: 'agent-progress-title', text: 'Live progress' }),
      stat('Gate check', progress.gate ? 'passed' : (running ? 'checking' : 'n/a')),
      stat('Open ports', progress.ports === null ? '...' : progress.ports),
      stat('Exploit matches', progress.exploits === null ? '...' : progress.exploits, progress.exploits > 0),
      stat('Checks approved', progress.plan),
      stat('Steps done', progress.done),
      stat('Steps failed', progress.failed, progress.failed > 0),
      h('div', { class: 'agent-links' },
        h('a', { class: 'btn quiet sm', href: '#/job/' + job.id, text: 'Tool steps in Live run' }),
        job.run_id ? h('a', { class: 'btn primary sm', href: '#/report/' + encodeURIComponent(job.run_id),
          text: 'Open report' }) : null,
        running ? null : h('button', { type: 'button', class: 'btn quiet sm', text: 'New agent scan',
          onclick: () => { job = null; showIdle(); } })));
  }

  function count(e) {
    if (e.kind === 'plan') {
      progress.gate = true;
      progress.plan = Array.isArray(e.actions)
        ? e.actions.filter((a) => a !== 'surface' && a !== 'exploits').length : 0;
    } else if (e.kind === 'ports' && Array.isArray(e.ports)) {
      progress.ports = e.ports.length;
    } else if (e.kind === 'step') {
      if (e.action === 'exploits' && e.status === 'done' && Number.isInteger(e.count)) {
        progress.exploits = e.count;
      }
      if (e.status === 'done') progress.done += 1;
      if (e.status === 'error') progress.failed += 1;
    }
  }

  async function poll() {
    if (!alive || !job) return;
    const res = await api.get('/api/scans/' + job.id + '/events?since=' + since);
    if (!alive) return;
    if (res.ok && isObject(res.data) && Array.isArray(res.data.events)) {
      for (const e of res.data.events) {
        if (!isObject(e)) continue;
        count(e);
        panel.apply(e);
      }
      since = Number.isInteger(res.data.next) ? res.data.next : since;
    }
    const meta = await api.get('/api/scans/' + job.id);
    if (!alive) return;
    if (meta.ok && isObject(meta.data)) job = Object.assign(job, meta.data);
    // Keep the Live run dot (and the background radar) in step with the scan.
    if (job.status === 'running') markRunning();
    else if (wasRunning) checkLive();
    wasRunning = job.status === 'running';
    panel.setJob(job.status);
    panel.setReport(job.status === 'running' ? '' : String(job.run_id || ''));
    panel.render();
    renderProgress();
    if (job.status === 'running' || (res.ok && res.data && res.data.more)) {
      timer = setTimeout(poll, 1000);
    }
  }

  function showSession() {
    since = 0;
    Object.assign(progress, { gate: false, ports: null, exploits: null, done: 0, failed: 0, plan: 0 });
    panel = createAgentPanel(job.id);
    panel.setJob(job.status);
    panel.render();
    renderProgress();
    grid.replaceChildren(panel.el, side);
    poll();
  }

  async function load() {
    const res = await api.get('/api/scans/latest');
    if (!alive) return;
    const latest = res.ok && isObject(res.data) && isObject(res.data.job) ? res.data.job : null;
    if (latest && String(latest.label || '').startsWith(AGENT_LABEL) && JOB_ID.test(String(latest.id))) {
      job = latest;
      showSession();
    } else {
      showIdle();
    }
  }

  load();
  return () => { alive = false; clearTimeout(timer); };
}
