/*
 * The Live run dot (DESIGN 5.4): shown whenever GET /api/scans/latest says a
 * job is running. Checked when the page loads, and every few seconds while a
 * job runs, whatever page is open. One timer for the whole app.
 */

import * as api from './api.js';
import { setLive } from './ui.js';

const LIVE_CHECK_MS = 4000;

let timer = null;
let shown = false;

/*
 * Ask the server for the latest job, update the dot, and keep checking while
 * one runs (or while the server does not answer and the dot is on).
 * Returns the response, so #/live can use the same answer.
 */
export async function checkLive() {
  clearTimeout(timer);
  timer = null;
  const res = await api.get('/api/scans/latest');
  const job = res.ok && res.data && res.data.job && typeof res.data.job === 'object'
    ? res.data.job : null;
  if (res.status !== 0) {
    shown = !!(job && job.status === 'running');
    setLive(shown);
  }
  if (shown) {
    clearTimeout(timer);
    timer = setTimeout(checkLive, LIVE_CHECK_MS);
  }
  return { res, job };
}

/* A page that just saw a job running: show the dot and keep it honest. */
export function markRunning() {
  if (shown) return;
  shown = true;
  setLive(true);
  clearTimeout(timer);
  timer = setTimeout(checkLive, LIVE_CHECK_MS);
}
