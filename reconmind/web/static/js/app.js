/*
 * ReconMind web app entry: a hash router.
 *
 *   #/new          New scan (the default)
 *   #/job/<id>     the job page for one scan (temporary; Live run replaces it)
 *   #/live, #/targets, #/hosts, #/system
 *                  a calm panel: these arrive in later steps
 *
 * Each view's mount function returns a cleanup function, called before the
 * next view mounts, so a view's timers never outlive it.
 */

import * as api from './api.js';
import { clone, JOB_ID } from './ui.js';
import { mountNewScan } from './views/newscan.js';
import { mountJob } from './views/job.js';

const LATER = { live: 'Live run', targets: 'Targets', hosts: 'Host lists', system: 'System' };

let cleanup = null;

function mountLater(view, name) {
  const { root, refs } = clone('tpl-later');
  refs.title.textContent = name;
  view.append(root);
  return null;
}

function setNav(key) {
  for (const link of document.querySelectorAll('.nav[data-route]')) {
    const on = link.dataset.route === key;
    link.classList.toggle('on', on);
    if (on) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
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
  } else if (parts.length === 2 && parts[0] === 'job' && JOB_ID.test(parts[1])) {
    mount = () => mountJob(view, parts[1]);
    navKey = 'live';
    title = 'Scan job';
  } else if (parts.length === 1 && Object.prototype.hasOwnProperty.call(LATER, parts[0])) {
    mount = () => mountLater(view, LATER[parts[0]]);
    navKey = parts[0];
    title = LATER[parts[0]];
  } else {
    location.replace('#/new');
    return;
  }

  if (cleanup) cleanup();
  cleanup = null;
  view.replaceChildren();
  setNav(navKey);
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

window.addEventListener('hashchange', route);
route();
loadScope();
