/*
 * The Live run dot (DESIGN 5.4): shown whenever GET /api/scans/latest says a
 * job is running. Checked when the page loads, and every few seconds while a
 * job runs, whatever page is open. One timer for the whole app.
 *
 * The check is quiet: when the server does not answer, or answers with
 * something unexpected, the dot goes off, nothing else is shown (no banner,
 * no notice), and the check tries again at the normal interval if it was
 * following a running job. It never throws.
 */

import * as api from './api.js';
import { setLive } from './ui.js';

const LIVE_CHECK_MS = 4000;

let timer = null;
let shown = false;
// The last check failed while a job was being followed: keep trying quietly.
let retrying = false;

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(checkLive, LIVE_CHECK_MS);
}

/*
 * Ask the server for the latest job, update the dot, and keep checking while
 * one runs. Returns {res, job}, so #/live can use the same answer.
 */
export async function checkLive() {
  clearTimeout(timer);
  timer = null;
  let res;
  try {
    res = await api.get('/api/scans/latest', { quiet: true });
  } catch (err) {
    res = { ok: false, status: 0, data: null };
  }
  const answered = !!(res.ok && res.data && typeof res.data === 'object' && 'job' in res.data);
  const job = answered && res.data.job && typeof res.data.job === 'object' ? res.data.job : null;
  if (answered) {
    shown = !!(job && job.status === 'running');
    retrying = false;
  } else {
    // Show nothing; try again at the normal interval if a job was being followed.
    retrying = shown || retrying;
    shown = false;
  }
  setLive(shown);
  if (shown || retrying) schedule();
  return { res, job };
}

/* A page that just saw a job running: show the dot and keep it honest. */
export function markRunning() {
  if (shown) return;
  shown = true;
  retrying = false;
  setLive(true);
  schedule();
}
