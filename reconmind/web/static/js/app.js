/*
 * ReconMind web app entry: a hash router.
 *
 *   #/new              New scan (the default)
 *   #/live             the scan running now; with none running, a short card
 *                      about the last scan (its report and how it ran). It
 *                      used to open the most
 *                      recently started one (the URL becomes #/job/<id>), or
 *                      a calm empty state when there is no scan at all
 *   #/job/<id>         Live run for one scan
 *   #/report/<run id>  the report of one saved run
 *   #/targets          Targets, with the newest folder open
 *   #/targets/<name>   Targets with that folder open
 *   #/system           System check and editable local AI and NVD settings
 *   #/setup            install or repair the scanning tools and the model
 *   #/agent            MORVAIN-X0, the AI agent: start a session or follow the latest one
 *   #/hosts            every host list; #/hosts/<list id> follows one list
 *   #/analyst/<id>     one of your own reports (Your reports on Targets)
 *
 * Each view's mount function returns a cleanup function, called before the
 * next view mounts, so a view's timers never outlive it. The body carries
 * data-view with the current view, so page only decoration (the New scan
 * light bars) can be shown from CSS.
 */

import * as api from './api.js';
import { checkLive } from './live.js';
import { clone, formatDayTime, h, isRunId, JOB_ID } from './ui.js';
import { mountNewScan } from './views/newscan.js';
import { mountJob } from './views/job.js';
import { mountReport } from './views/report.js';
import { mountTargets } from './views/targets.js';
import { mountSystem } from './views/system.js';
import { mountSetup } from './views/setup.js';
import { mountMorvain } from './views/morvain.js';
import { mountHosts } from './views/hosts.js';
import { mountAnalyst } from './views/analyst.js';

let cleanup = null;

/* #/live: the running scan's page. With none running, say so, and point to the last one. */
function mountLive(view) {
  let alive = true;
  checkLive().then(({ res, job }) => {
    if (!alive) return;
    if (job && JOB_ID.test(String(job.id)) && job.status === 'running') {
      location.replace('#/job/' + job.id);
      return;
    }
    const { root, refs } = clone('tpl-live-empty');
    if (job && JOB_ID.test(String(job.id))) {
      const label = typeof job.label === 'string' && job.label ? job.label : 'The last scan';
      const words = { done: 'finished', failed: 'failed', stopped: 'was stopped', refused: 'was refused by the gate',
        interrupted: 'was interrupted' }[job.status] || 'ended';
      const when = formatDayTime(job.finished || job.started);
      refs.text.textContent = 'No scan is running right now. The last one, ' + label + ', ' + words
        + (when ? ' on ' + when : '') + '.';
      const links = [];
      if (isRunId(job.run_id)) links.push(h('a', { class: 'btn primary', href: '#/report/' + encodeURIComponent(job.run_id), text: 'Open its report' }));
      links.push(h('a', { class: 'btn quiet', href: '#/job/' + job.id, text: 'See how it ran' }));
      refs.actions.prepend(...links);
    }
    if (res.status === 0) {
      refs.text.textContent = 'The latest scan could not be loaded. The ReconMind server is not answering.';
    } else if (!res.ok) {
      refs.text.textContent = 'The latest scan could not be loaded. The server answered with status '
        + res.status + '.';
    } else if (!res.data || typeof res.data !== 'object') {
      refs.text.textContent = 'The latest scan could not be read. Reload to try again.';
    }
    view.replaceChildren(root);
  });
  return () => { alive = false; };
}

function setNav(key) {
  for (const link of document.querySelectorAll('.nav[data-route]')) {
    const on = link.dataset.route === key;
    link.classList.toggle('on', on);
    if (on) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

/* A decoded hash part, or null when it is not valid percent encoding. */
function decodePart(part) {
  try {
    return decodeURIComponent(part);
  } catch (err) {
    return null;
  }
}

function route() {
  const parts = (location.hash || '#/new').replace(/^#\/?/, '').split('/');
  const view = document.getElementById('view');

  let mount;
  let navKey;
  let title;
  if (parts.length === 1 && (parts[0] === 'new' || parts[0] === '')) {
    mount = () => mountNewScan(view);
    navKey = 'new';
    title = 'New scan';
  } else if (parts.length === 1 && parts[0] === 'live') {
    mount = () => mountLive(view);
    navKey = 'live';
    title = 'Live run';
  } else if (parts.length === 2 && parts[0] === 'job') {
    // An id no job can have still opens Live run, which says there is no
    // scan with that id (mountJob never sends it to the server).
    const jobId = JOB_ID.test(parts[1]) ? parts[1] : '';
    mount = () => mountJob(view, jobId);
    navKey = 'live';
    title = 'Live run';
  } else if (parts.length === 2 && parts[0] === 'report') {
    // An id no run can have still opens Report, which says there is no
    // report with that id (mountReport checks isRunId before asking).
    const decoded = decodePart(parts[1]);
    const runId = isRunId(decoded) ? decoded : '';
    mount = () => mountReport(view, runId);
    navKey = 'targets';
    title = 'Report';
  } else if (parts[0] === 'targets' && (parts.length === 1
      || (parts.length === 2 && decodePart(parts[1]) !== null))) {
    const wanted = parts.length === 2 ? decodePart(parts[1]) : null;
    mount = () => mountTargets(view, wanted);
    navKey = 'targets';
    title = 'Targets';
  } else if (parts.length === 1 && parts[0] === 'system') {
    mount = () => mountSystem(view);
    navKey = 'system';
    title = 'System check';
  } else if (parts.length === 1 && parts[0] === 'agent') {
    mount = () => mountMorvain(view);
    navKey = 'agent';
    title = 'MORVAIN-X0';
  } else if (parts.length === 1 && parts[0] === 'setup') {
    mount = () => mountSetup(view);
    navKey = 'system';
    title = 'Setup';
  } else if (parts[0] === 'hosts' && parts.length <= 2) {
    const listId = parts.length === 2 ? parts[1] : null;
    mount = () => mountHosts(view, listId);
    navKey = 'hosts';
    title = 'Host lists';
  } else if (parts.length === 2 && parts[0] === 'analyst') {
    const reportId = /^[0-9a-f]{16}$/.test(parts[1]) ? parts[1] : '';
    mount = () => mountAnalyst(view, reportId);
    navKey = 'targets';
    title = 'Your report';
  } else {
    location.replace('#/new');
    return;
  }

  if (cleanup) cleanup();
  cleanup = null;
  view.replaceChildren();
  setNav(navKey);
  document.body.dataset.view = navKey;
  document.title = title + ' | ReconMind';
  cleanup = mount() || null;
  window.scrollTo(0, 0);
}

async function loadScope() {
  const res = await api.options();
  if (!res.ok || !res.data || !Array.isArray(res.data.allowlist)) return;
  const n = res.data.allowlist.length;
  document.getElementById('scope-text').textContent =
    'Scope locked to ' + n + (n === 1 ? ' lab network' : ' lab networks');
}

const openedOnLive = /^#\/live$/.test(location.hash);
window.addEventListener('hashchange', route);
route();
loadScope();
// #/live asks on its own; every other first page checks once for the Live run dot.
if (!openedOnLive) checkLive();
