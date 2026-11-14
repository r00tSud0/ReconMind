/*
 * Job view (#/job/<id>). Temporary: the Live run screen replaces it in a
 * later step.
 *
 * Polls GET /api/scans/<id> every second while the job runs and shows the
 * label, a status pill, the elapsed time, a Stop button and the raw output
 * lines. The output comes from the target's tools, so it is set with
 * textContent only.
 */

import * as api from '../api.js';
import { clone, formatElapsed, parseTime, setLive } from '../ui.js';

const POLL_MS = 1000;
const LIVE_CHECK_MS = 5000;

const STATUS_WORDS = {
  running: 'Running',
  done: 'Finished',
  failed: 'Failed',
  refused: 'Refused',
  stopped: 'Stopped',
  interrupted: 'Interrupted',
};

/* What each ending means and what to do next. */
function endNote(job) {
  switch (job.status) {
    case 'done':
      return job.run_id
        ? ['The scan finished', 'The report is saved in reports/' + job.run_id + '/report.md. The report view arrives in a later step.']
        : ['The scan finished', 'The output above shows where the report was saved.'];
    case 'refused':
      return ['The authorization gate refused the target', 'Nothing was sent to that address. The refusal is saved in the report history.'];
    case 'failed':
      return ['The scan did not finish', (job.exit_code === null || job.exit_code === undefined
        ? 'It could not be started or followed.' : 'It ended with exit code ' + job.exit_code + '.')
        + ' The last lines of the output say why.'];
    case 'stopped':
      return ['The scan was stopped', 'The scan and every tool it started were stopped, so it most likely wrote no report.'];
    case 'interrupted':
      return ['The web server stopped while this scan ran', 'Its end was not recorded. Check reports/ for a finished report before scanning again.'];
    default:
      return null;
  }
}

/* After leaving a running job's page, keep the Live run dot honest until it ends. */
let liveWatch = null;

function watchLive(jobId) {
  clearTimeout(liveWatch);
  const check = async () => {
    const res = await api.get('/api/scans/' + jobId);
    if (res.ok && res.data && res.data.status === 'running') {
      liveWatch = setTimeout(check, LIVE_CHECK_MS);
    } else if (res.status !== 0) {
      setLive(false);
    } else {
      liveWatch = setTimeout(check, LIVE_CHECK_MS);
    }
  };
  liveWatch = setTimeout(check, LIVE_CHECK_MS);
}

export function mountJob(view, jobId) {
  clearTimeout(liveWatch);
  const { root, refs } = clone('tpl-job');
  view.append(root);

  let alive = true;
  let pollTimer = null;
  let tickTimer = null;
  let job = null;
  let shownOutput = null;
  let shownEnd = null;

  function renderElapsed() {
    if (!job) return;
    const started = parseTime(job.started);
    if (!started) return;
    const end = parseTime(job.finished) || new Date();
    refs.elapsed.textContent = 'Elapsed ' + formatElapsed((end - started) / 1000);
  }

  function renderNote() {
    const note = endNote(job);
    const key = note ? job.status + job.run_id : null;
    if (key === shownEnd) return;
    shownEnd = key;
    refs.alert.replaceChildren();
    if (!note) return;
    const { root: box, refs: r } = clone('tpl-notice');
    r.title.textContent = note[0];
    r.text.textContent = note[1];
    if (job.status === 'done' || job.status === 'refused') {
      const again = document.createElement('a');
      again.className = 'btn quiet';
      again.href = '#/new';
      again.textContent = 'Start another scan';
      r.extra.append(again);
    }
    refs.alert.append(box);
  }

  function render() {
    const running = job.status === 'running';
    refs.label.textContent = job.label || 'Scan';
    document.title = (job.label || 'Scan') + ' | ReconMind';
    refs.status.textContent = STATUS_WORDS[job.status] || String(job.status);
    refs.status.className = 'pill ' + (STATUS_WORDS[job.status] ? job.status : '');
    refs.stop.hidden = !running;
    refs.runid.hidden = !job.run_id;
    refs.runidValue.textContent = job.run_id || '';
    setLive(running);
    renderElapsed();

    const text = Array.isArray(job.lines) ? job.lines.map(String).join('\n') : '';
    if (text !== shownOutput) {
      const out = refs.out;
      // Follow new lines only when the reader is already at the bottom.
      const atBottom = out.scrollTop + out.clientHeight >= out.scrollHeight - 24;
      out.textContent = text;
      if (atBottom) out.scrollTop = out.scrollHeight;
      shownOutput = text;
    }
    renderNote();
  }

  function notFound() {
    refs.label.textContent = 'Scan not found';
    refs.status.textContent = 'Unknown';
    refs.status.className = 'pill';
    const { root: box, refs: r } = clone('tpl-notice');
    r.title.textContent = 'There is no scan with this id';
    r.text.textContent = 'Jobs are kept in reports/.jobs. Start a new scan from New scan.';
    refs.alert.replaceChildren(box);
  }

  async function poll() {
    const res = await api.get('/api/scans/' + jobId);
    if (!alive) return;
    if (res.status === 404) {
      notFound();
      return;
    }
    if (res.ok && res.data) {
      job = res.data;
      render();
    }
    // Keep polling while the job runs, and keep trying while the server is unreachable.
    if (!job || job.status === 'running' || !res.ok) {
      pollTimer = setTimeout(poll, POLL_MS);
    }
  }

  refs.stop.addEventListener('click', async () => {
    refs.stop.disabled = true;
    refs.stop.textContent = 'Stopping';
    const res = await api.post('/api/scans/' + jobId + '/stop', {});
    if (!alive) return;
    refs.stop.disabled = false;
    refs.stop.textContent = 'Stop scan';
    if (res.ok && res.data) {
      job = res.data;
      render();
    }
  });

  tickTimer = setInterval(renderElapsed, 1000);
  poll();

  return () => {
    alive = false;
    clearTimeout(pollTimer);
    clearInterval(tickTimer);
    if (job && job.status === 'running') watchLive(jobId);
    else setLive(false);
  };
}
