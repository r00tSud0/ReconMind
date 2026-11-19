/*
 * Setup (#/setup): installs or repairs ReconMind's scanning tools and model.
 * The page only starts the installer (python3 -m reconmind.setup) and shows
 * its progress. Nothing here scans, and the allowed networks never change.
 * No server or user text is parsed as HTML.
 */
import * as api from '../api.js';
import { h } from '../ui.js';

const asObject = (x) => x && typeof x === 'object' && !Array.isArray(x) ? x : {};
const asList = (x) => Array.isArray(x) ? x : [];
const label = (value) => value === null || value === undefined ? '' : String(value);

const STEP_WORDS = { running: 'Working', done: 'Done', skipped: 'Already fine', failed: 'Failed' };

function status(text, good) {
  return h('span', { class: 'sys-status' + (good ? ' good' : ''), text });
}
function row(name, detail, state, good) {
  return h('div', { class: 'sys-row' },
    h('div', { class: 'sys-row-id' },
      h('strong', { text: label(name) }),
      detail ? h('span', { class: 'help', text: label(detail) }) : null),
    status(label(state), good));
}
function section(title, ...contents) {
  return h('section', { class: 'glass sys-panel reveal' },
    h('h2', { class: 'h2', text: title }), ...contents);
}

export function mountSetup(view) {
  let alive = true;
  let timer = null;
  const root = h('main', { class: 'page page-wide system-page setup-page' });
  const title = h('h1', { class: 'title', text: 'Setup' });
  const summary = h('p', { class: 'help', text: 'Checking this computer.' });
  const reload = h('button', { class: 'btn quiet', type: 'button', text: 'Check again' });
  const install = h('button', { class: 'btn primary', type: 'button', text: 'Install or repair' });
  const head = h('header', { class: 'sys-header' }, h('div', {}, title, summary),
    h('div', { class: 'sys-setting-actions setup-actions' }, reload, install));
  const notice = h('p', { class: 'sys-feedback help', role: 'status', 'aria-live': 'polite' });
  const body = h('div', { class: 'system-grid' });
  const progress = h('div', { class: 'setup-progress' });
  root.append(head, notice, progress, body);
  view.append(root);

  function renderSnapshot(d) {
    const tools = asList(d.tools);
    const ready = tools.filter((t) => t.status === 'ready').length;
    const model = asObject(d.model);
    summary.textContent = ready + ' of ' + tools.length + ' security tools ready. Model '
      + (model.files_present ? 'files present.' : 'not installed.');
    install.disabled = !!d.blocked;

    const about = section('Before you start',
      h('p', { class: 'help', text: 'ReconMind scans only lab networks you own or are '
        + 'allowed to test. Setup installs programs and the ATT&CK model. It never scans '
        + 'anything and cannot change the allowed or blocked networks.' }),
      h('p', { class: 'help', text: 'Running setup again repairs anything missing and skips '
        + 'what is already in place.' }));
    const pre = section('Preflight', ...asList(d.preflight).map((c) => row(c.name, c.detail,
      c.ok ? 'OK' : (c.blocking ? 'Blocked' : 'Note'), !!c.ok)));
    const parts = section('Components',
      ...tools.map((t) => row(t.name, t.action, t.status === 'ready' ? 'Ready' : 'Missing',
        t.status === 'ready')),
      row('ATT&CK mapper model', 'SciBERT Run 3, ' + label(model.labels) + ' techniques',
        model.files_present ? 'Files present' : 'Missing', !!model.files_present));
    const plan = asList(d.plan);
    const planPanel = section('What setup does',
      plan.length
        ? h('ol', { class: 'setup-plan' }, ...plan.map((p) => h('li', {},
          h('strong', { text: label(p.title) }), h('span', { class: 'help', text: label(p.detail) }))))
        : h('p', { class: 'help', text: 'No plan, because preflight is blocked.' }));
    body.replaceChildren(h('div', { class: 'sys-stack' }, about, pre),
      h('div', { class: 'sys-stack' }, parts, planPanel));
  }

  function renderStatus(s) {
    const st = asObject(s);
    if (!st.state || st.state === 'idle') {
      progress.replaceChildren();
      return;
    }
    const steps = asList(st.steps);
    const total = Number(st.total) || steps.length;
    const doneCount = steps.filter((x) => x.state && x.state !== 'running').length;
    let headline = 'Setup is running. Step ' + Math.min(doneCount + 1, total || 1)
      + ' of ' + (total || '?') + '.';
    const result = asObject(st.result);
    if (st.state === 'done') headline = 'Setup complete. All tools are ready.';
    else if (st.state === 'failed') {
      const failed = asList(result.failed).length;
      headline = st.blocked ? 'Setup could not start: preflight is blocked.'
        : failed ? failed + (failed === 1 ? ' step' : ' steps') + ' failed. Fix the cause, then select Install or repair again.'
          : 'Setup stopped before it finished.';
    }
    const list = h('div', { class: 'setup-steps' }, ...steps.map((x) => h('div', {
      class: 'setup-step ' + label(x.state) },
    h('span', { class: 'setup-step-n num', text: label(x.index) }),
    h('div', { class: 'sys-row-id' },
      h('strong', { text: label(x.title) }),
      x.message ? h('span', { class: 'help', text: label(x.message) }) : null),
    status(STEP_WORDS[x.state] || label(x.state), x.state === 'done' || x.state === 'skipped'))));
    const log = h('pre', { class: 'setup-log', tabindex: '0', 'aria-label': 'Setup log' },
      asList(st.log).slice(-60).join('\n'));
    progress.replaceChildren(section('Progress',
      h('p', { class: 'help' + (st.state === 'failed' ? ' setup-bad' : ''), text: headline }),
      list,
      h('details', { class: 'setup-details' }, h('summary', { text: 'Show the setup log' }), log)));
    install.disabled = st.state === 'running';
    reload.disabled = st.state === 'running';
  }

  async function load() {
    reload.disabled = true;
    const res = await api.get('/api/setup');
    if (!alive) return;
    reload.disabled = false;
    if (!res.ok || !res.data || typeof res.data !== 'object') {
      summary.textContent = res.status === 0 ? 'The ReconMind server is not answering.'
        : 'The setup check could not be loaded.';
      return;
    }
    renderSnapshot(res.data);
    renderStatus(res.data.job);
    if (asObject(res.data.job).state === 'running') poll();
  }

  async function poll() {
    clearTimeout(timer);
    const res = await api.get('/api/setup/status');
    if (!alive) return;
    if (res.ok && res.data) {
      renderStatus(res.data);
      if (res.data.state === 'running') {
        timer = setTimeout(poll, 1000);
        return;
      }
      api.invalidateOptions();
      load();
      return;
    }
    timer = setTimeout(poll, 2000);
  }

  install.addEventListener('click', async () => {
    install.disabled = true;
    notice.classList.remove('bad');
    notice.textContent = 'Starting setup.';
    const res = await api.post('/api/setup/install', {});
    if (!alive) return;
    if (!res.ok) {
      notice.classList.add('bad');
      notice.textContent = res.data && res.data.message ? label(res.data.message)
        : 'Setup could not start.';
      install.disabled = false;
      return;
    }
    notice.textContent = 'Setup started. You can leave this page; it keeps running.';
    renderStatus(asObject(res.data).status);
    poll();
  });
  reload.addEventListener('click', load);
  load();
  return () => { alive = false; clearTimeout(timer); };
}
