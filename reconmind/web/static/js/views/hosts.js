/*
 * Host lists (#/hosts and #/hosts/<list id>), matching
 * docs/design/screens/06_Batch.html.
 *
 * A host list is up to 8 lab machines scanned one after another with the
 * same settings (started from New scan, Host list). Every host passed the
 * authorization gate before the list started, and each one gets its own
 * report in its own target folder. This page reads GET /api/lists/<id> every
 * 2 seconds while the list runs: a progress bar with one segment per host,
 * then one row per host with its status, worst finding and a link to watch it
 * live or open its report. "Stop after this host" lets the current host
 * finish and starts no more.
 *
 * #/hosts with no id shows every list, newest first.
 *
 * Every value from the server is set with textContent or attributes, never as
 * markup.
 */

import * as api from '../api.js';
import { checkLive, markRunning } from '../live.js';
import { formatDayTime, h, heat, isRunId, JOB_ID, plural, SEVERITIES } from '../ui.js';

const LIST_ID = /^[0-9a-f]{10}$/;
const POLL_MS = 2000;
const STATUS_WORDS = {
  waiting: 'Waiting', running: 'Scanning now', done: 'Done', failed: 'Failed', refused: 'Refused by the gate',
  stopped: 'Stopped', interrupted: 'Interrupted', skipped: 'Not scanned',
};
const LIST_WORDS = { done: 'Finished', stopped: 'Stopped', interrupted: 'Interrupted', failed: 'Failed' };

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v) => (typeof v === 'string' ? v : '');

function worst(host) {
  const f = isObject(host.findings) ? host.findings : null;
  if (!f) return null;
  for (const s of SEVERITIES) {
    const n = Number(f[s]) || 0;
    if (n) return { severity: s, count: n };
  }
  return { severity: null, count: 0 };
}

function hostRow(host, index) {
  const status = text(host.status) || 'waiting';
  const w = worst(host);
  const parts = [
    h('div', { class: 'hl-who' },
      h('span', { class: 'hl-ip num', text: text(host.target) }),
      h('span', { class: 'help hl-status st-' + status, text: STATUS_WORDS[status] || status })),
  ];
  if (w && w.severity) {
    parts.push(h('div', { class: 'hl-worst' }, heat(w.severity),
      h('span', { text: w.count + ' ' + w.severity })));
  } else if (w) {
    parts.push(h('div', { class: 'hl-worst' }, h('span', { class: 'help', text: 'No findings' })));
  } else {
    parts.push(h('div', { class: 'hl-worst' }));
  }
  if (Number.isInteger(host.open_ports)) {
    parts.push(h('span', { class: 'help hl-ports', text: plural(host.open_ports, 'open port', 'open ports') }));
  }
  let action = null;
  if (isRunId(host.run_id)) {
    action = h('a', { class: 'btn quiet btn-small', href: '#/report/' + encodeURIComponent(host.run_id), text: 'Open report' });
  } else if (status === 'running' && JOB_ID.test(text(host.job_id))) {
    action = h('a', { class: 'btn primary btn-small', href: '#/job/' + host.job_id, text: 'Watch live' });
  } else if (JOB_ID.test(text(host.job_id))) {
    action = h('a', { class: 'btn quiet btn-small', href: '#/job/' + host.job_id, text: 'Open the run' });
  }
  parts.push(h('div', { class: 'hl-action' }, action));
  const row = h('div', { class: 'scan hl-row' + (status === 'running' ? ' running' : '') }, ...parts);
  row.style.animationDelay = (index * 0.06) + 's';
  return row;
}

function segments(hosts) {
  return h('div', { class: 'hl-segs', role: 'img',
    'aria-label': hosts.map((x) => text(x.target) + ' ' + (STATUS_WORDS[x.status] || x.status)).join(', ') },
  ...hosts.map((x) => h('div', { class: 'hl-seg' }, h('i', { class: 'st-' + text(x.status) }))));
}

function counts(hosts) {
  const by = {};
  for (const x of hosts) by[x.status] = (by[x.status] || 0) + 1;
  return h('div', { class: 'hl-counts' }, ...Object.entries(by).map(([s, n]) =>
    h('span', {}, h('b', { class: 'st-' + s, text: String(n) }), ' ' + (STATUS_WORDS[s] || s).toLowerCase())));
}

export function mountHosts(view, listId) {
  let alive = true;
  let timer = null;
  const page = h('main', { class: 'page page-wide hosts-page' });
  view.append(page);

  function empty(title, body) {
    page.replaceChildren(h('section', { class: 'glass later reveal' },
      h('h1', { class: 'h2 later-title', text: title }),
      h('p', { class: 'help', text: body }),
      h('a', { class: 'btn primary', href: '#/new', text: 'Start a host list on New scan' })));
  }

  function renderOne(data) {
    const hosts = Array.isArray(data.hosts) ? data.hosts.filter(isObject) : [];
    const running = data.status === 'running';
    if (running) markRunning();
    else checkLive();
    const current = hosts.findIndex((x) => x.status === 'running');
    const head = running
      ? h('div', { class: 'hl-live' }, h('span', { class: 'live-pulse', 'aria-hidden': 'true' }),
        current >= 0 ? 'Scanning host ' + (current + 1) + ' of ' + hosts.length : 'Starting the next host')
      : h('div', { class: 'hl-live done', text: (LIST_WORDS[data.status] || 'Finished') + ', '
        + plural(hosts.length, 'host', 'hosts') });
    const stop = h('button', { type: 'button', class: 'btn quiet', text: data.stop_after ? 'Stops after this host' : 'Stop after this host' });
    stop.disabled = !running || !!data.stop_after;
    stop.addEventListener('click', async () => {
      stop.disabled = true;
      const res = await api.post('/api/lists/' + listId + '/stop', {});
      if (alive && res.ok) stop.textContent = 'Stops after this host';
    });
    const started = formatDayTime(data.started);
    const lines = [
      h('div', { class: 'hl-head reveal' },
        h('div', { class: 'hl-title' }, head,
          h('h1', { class: 'title page-title', text: 'Host list' }),
          h('p', { class: 'lead', text: text(data.label) + ', one host at a time.'
            + (started ? ' Started ' + started + '.' : '') })),
        running ? stop : h('a', { class: 'btn quiet', href: '#/hosts', text: 'All host lists' })),
      h('section', { class: 'glass hl-progress reveal' }, segments(hosts), counts(hosts)),
      h('section', { class: 'scan-list', 'aria-label': 'Hosts' }, ...hosts.map(hostRow)),
      h('p', { class: 'help', text: 'Each host gets its own report in its own target folder. '
        + 'Every host was checked against the allowlist before the list started, and the scan '
        + 'checks it again before it sends anything.' }),
    ];
    if (text(data.warning)) lines.splice(2, 0, h('div', { class: 'alert grey' }, h('p', { text: data.warning })));
    page.replaceChildren(...lines);
    if (running) timer = setTimeout(load, POLL_MS);
  }

  function renderAll(lists) {
    if (!lists.length) {
      empty('No host lists yet', 'A host list scans up to 8 lab machines one after another with the same '
        + 'settings. Pick Host list on New scan to start one.');
      return;
    }
    page.replaceChildren(
      h('div', { class: 'hl-head reveal' },
        h('div', { class: 'hl-title' }, h('h1', { class: 'title page-title', text: 'Host lists' }),
          h('p', { class: 'lead', text: 'Every host list, newest first. Each host keeps its own report.' })),
        h('a', { class: 'btn primary', href: '#/new', text: 'New host list' })),
      h('section', { class: 'scan-list' }, ...lists.map((l, i) => {
        const hosts = Array.isArray(l.hosts) ? l.hosts : [];
        const done = hosts.filter((x) => x.status === 'done').length;
        const row = h('a', { class: 'scan', href: '#/hosts/' + l.id },
          h('span', { class: 'scan-text' },
            h('span', { class: 'scan-name', text: text(l.label) }),
            h('span', { class: 'help', text: (formatDayTime(l.started) || '') + '. '
              + done + ' of ' + plural(hosts.length, 'host', 'hosts') + ' done. '
              + hosts.map((x) => text(x.target)).join(', ') })),
          h('span', { class: 'scan-tag' + (l.status === 'running' ? ' live' : ' muted'),
            text: l.status === 'running' ? 'Running' : (LIST_WORDS[l.status] || 'Finished') }));
        row.style.animationDelay = (i * 0.05) + 's';
        return row;
      })));
    if (lists.some((l) => l.status === 'running')) timer = setTimeout(load, POLL_MS * 2);
  }

  async function load() {
    timer = null;
    const res = await api.get(listId ? '/api/lists/' + listId : '/api/lists');
    if (!alive) return;
    if (res.status === 0) {
      empty('The ReconMind server is not answering', 'Check that ReconMind is still running, then reload.');
      timer = setTimeout(load, POLL_MS * 2);
      return;
    }
    if (listId) {
      if (!res.ok || !isObject(res.data)) {
        empty('There is no host list with that id', 'It may belong to a ReconMind folder that was cleared.');
        return;
      }
      document.title = 'Host list | ReconMind';
      renderOne(res.data);
    } else {
      renderAll(res.ok && isObject(res.data) && Array.isArray(res.data.lists) ? res.data.lists.filter(isObject) : []);
    }
  }

  if (listId && !LIST_ID.test(listId)) empty('There is no host list with that id', 'Check the address.');
  else load();
  return () => {
    alive = false;
    if (timer) clearTimeout(timer);
  };
}
