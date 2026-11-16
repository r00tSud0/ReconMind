/*
 * Job view (#/job/<id>).
 *
 * Polls GET /api/scans/<id> every second while the job runs and shows the
 * label, a status pill, the elapsed time, a Stop button (with an in page
 * confirmation dialog), a one line status of the step that runs now, and the
 * technical log, folded by default. The log comes from the target's tools,
 * so it is set with textContent only.
 *
 * The status line translates the CLI's "[RUN    ] <tool>", "[DONE   ] <tool>"
 * and "analysis:" lines into plain words, using the actions and their tools
 * from /api/options. Lines that do not match are not shown there.
 *
 * Every request is checked: a server that does not answer, an answer that is
 * not JSON and an unexpected status each give a calm notice, and the page
 * keeps trying. Nothing here throws out of a timer or a click.
 */

import * as api from '../api.js';
import { checkLive, markRunning } from '../live.js';
import { clone, formatElapsed, h, parseTime } from '../ui.js';
import { ACTION_COPY } from './newscan.js';

const POLL_MS = 1000;

const STATUS_WORDS = {
  running: 'Running',
  done: 'Finished',
  failed: 'Failed',
  refused: 'Refused',
  stopped: 'Stopped',
  interrupted: 'Interrupted',
};

const SAVED = 'The scan finished and the report is saved in the report history.';
const ATTACK_TOOL = 'attack_map';
const ATTACK_RUN = 'Mapping findings to MITRE ATT&CK';
const ATTACK_DONE = 'Finished mapping findings to MITRE ATT&CK';
const ANALYSIS_TEXT = 'Writing the AI analysis';
const HIDDEN_LOG_PREFIX = 'Loading weights';
// "[RUN    ] nmap_scan" or "[DONE   ] web_fingerprint port 80".
const STEP_LINE = /^\[(RUN|DONE)\s*\]\s+([A-Za-z0-9_]+)(?: port (\d+))?\s*$/;

/* What each ending means and what to do next. */
function endNote(job) {
  switch (job.status) {
    case 'done':
      // A finished report without the AI summary: say so calmly, the tool results are all there.
      return typeof job.warning === 'string' && job.warning ? job.warning + ' ' + SAVED : SAVED;
    case 'refused':
      return 'The authorization gate refused the target. Nothing was sent to that address. '
        + 'The refusal is saved in the report history.';
    case 'failed':
      return 'The scan did not finish. '
        + (job.exit_code === null || job.exit_code === undefined
          ? 'It could not be started or followed.' : 'It ended with exit code ' + job.exit_code + '.')
        + ' Open the technical log below to see why.';
    case 'stopped':
      return 'The scan was stopped. Everything that finished before the stop is saved as a partial '
        + 'report, marked Stopped in the report history.';
    case 'interrupted':
      return 'The ReconMind server stopped while this scan ran, so its end was not recorded. '
        + 'Look in the report history before scanning again.';
    default:
      return null;
  }
}

const isJob = (data) => !!data && typeof data === 'object' && !Array.isArray(data)
  && typeof data.status === 'string';

export function mountJob(view, jobId) {
  const { root, refs } = clone('tpl-job');
  view.append(root);

  let alive = true;
  let pollTimer = null;
  let pollPending = false;
  let tickTimer = null;
  let job = null;
  let shownOutput = null;
  let shownEnd = null;
  let shownProblem = null;
  let wasRunning = false;
  let stopping = false;
  let gone = false;
  // Agent tool name to "Surface Map (nmap)", from /api/options.
  let toolNames = {};

  // ---- notices ---------------------------------------------------------

  function notice(title, text, extra) {
    const { root: box, refs: r } = clone('tpl-notice');
    r.title.textContent = title || '';
    r.title.hidden = !title;
    r.text.textContent = text || '';
    if (extra) r.extra.append(extra);
    return box;
  }

  /* A problem with the requests themselves; shown once until it changes. */
  function showProblem(title, text) {
    const key = title + '|' + text;
    if (key === shownProblem) return;
    shownProblem = key;
    refs.problem.replaceChildren(notice(title, text));
  }

  function clearProblem() {
    if (shownProblem === null) return;
    shownProblem = null;
    refs.problem.replaceChildren();
  }

  function requestProblem(res, what) {
    if (res.status === 0) {
      showProblem('The ReconMind server is not answering', 'This page tries again every second.');
    } else if (res.ok) {
      showProblem(what + ' could not be read', 'The server sent an answer the page could not read. This page keeps trying.');
    } else {
      showProblem(what + ' could not be loaded', 'The server answered with status ' + res.status
        + '. This page keeps trying.');
    }
  }

  // ---- the status line -------------------------------------------------

  function loadToolNames() {
    api.options().then((res) => {
      if (!alive || !res.ok) return;
      const names = {};
      for (const action of res.data.actions) {
        const copy = ACTION_COPY[action.id];
        const label = action.name + (copy ? ' (' + copy.tool + ')' : '');
        for (const tool of action.tools) names[tool] = label;
      }
      toolNames = names;
      if (job) render();
    }).catch(() => {});
  }

  function stepText(line) {
    const m = STEP_LINE.exec(line);
    if (m) {
      const [, kind, tool, port] = m;
      if (tool === ATTACK_TOOL) return kind === 'RUN' ? ATTACK_RUN : ATTACK_DONE;
      const name = Object.prototype.hasOwnProperty.call(toolNames, tool) ? toolNames[tool] : null;
      if (!name) return null;
      return (kind === 'RUN' ? 'Running ' : 'Finished ') + name + (port ? ' on port ' + port : '');
    }
    // "analysis:    skipped" and "analysis:    failed" say nothing is being written.
    if (line.startsWith('analysis:') && !/^analysis:\s*(skipped|failed)/.test(line)) {
      return ANALYSIS_TEXT;
    }
    return null;
  }

  function currentStep(lines) {
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      const text = stepText(lines[i]);
      if (text) return text;
    }
    return '';
  }

  // ---- rendering -------------------------------------------------------

  function renderElapsed() {
    if (!job) return;
    const started = parseTime(job.started);
    if (!started) return;
    const end = parseTime(job.finished) || new Date();
    refs.elapsed.textContent = 'Elapsed ' + formatElapsed((end - started) / 1000);
  }

  function renderStop(running) {
    refs.stop.hidden = !(running || stopping);
    refs.stop.disabled = stopping;
    refs.stop.setAttribute('aria-busy', stopping ? 'true' : 'false');
    refs.stopSpinner.hidden = !stopping;
    refs.stopLabel.textContent = stopping ? 'Stopping' : 'Stop scan';
    if (!running && refs.stopDialog.open) refs.stopDialog.close();
  }

  function renderNote() {
    // While a stop is in flight the partial report is still being saved: wait for it.
    const text = stopping ? null : endNote(job);
    const key = text ? job.status + '|' + text : null;
    if (key === shownEnd) return;
    shownEnd = key;
    refs.alert.replaceChildren();
    if (!text) return;
    let extra = null;
    if (job.status === 'done' || job.status === 'refused') {
      extra = h('a', { class: 'btn quiet', href: '#/new', text: 'Start another scan' });
    }
    refs.alert.append(notice(null, text, extra));
  }

  function render() {
    const running = job.status === 'running';
    const label = typeof job.label === 'string' && job.label ? job.label : 'Scan';
    refs.label.textContent = label;
    document.title = label + ' | ReconMind';
    refs.status.textContent = STATUS_WORDS[job.status] || String(job.status);
    refs.status.className = 'pill ' + (STATUS_WORDS[job.status] ? job.status : '');
    renderStop(running);
    const runId = typeof job.run_id === 'string' ? job.run_id : '';
    refs.runid.hidden = !runId;
    refs.runidValue.textContent = runId;
    // This page may show an older job while another one runs, so a job that
    // is not running asks the server instead of turning the dot off.
    if (running) markRunning();
    else if (wasRunning) checkLive();
    wasRunning = running;
    renderElapsed();

    const lines = Array.isArray(job.lines) ? job.lines.map(String) : [];
    const step = running ? currentStep(lines) : '';
    refs.step.hidden = !step;
    if (refs.step.textContent !== step) refs.step.textContent = step;

    const text = lines.filter((line) => !line.startsWith(HIDDEN_LOG_PREFIX)).join('\n');
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
    gone = true;
    clearTimeout(pollTimer);
    if (refs.stopDialog.open) refs.stopDialog.close();
    refs.label.textContent = 'Scan not found';
    document.title = 'Scan not found | ReconMind';
    refs.status.textContent = 'Unknown';
    refs.status.className = 'pill';
    refs.elapsed.textContent = '';
    refs.stop.hidden = true;
    refs.step.hidden = true;
    refs.runid.hidden = true;
    refs.logPanel.hidden = true;
    refs.problem.replaceChildren();
    shownProblem = null;
    const link = h('a', { class: 'btn quiet', href: '#/new', text: 'Go to New scan' });
    refs.alert.replaceChildren(notice(null, 'There is no scan with that id.', link));
  }

  // ---- polling ---------------------------------------------------------

  /* One poll loop at a time: a timer is waiting or a request is in flight. */
  function schedulePoll() {
    if (pollPending || gone || !alive) return;
    pollPending = true;
    pollTimer = setTimeout(poll, POLL_MS);
  }

  async function poll() {
    pollPending = true;
    let res;
    try {
      res = await api.get('/api/scans/' + jobId);
    } catch (err) {
      res = { ok: false, status: 0, data: null };
    }
    pollPending = false;
    if (!alive || gone) return;
    if (res.status === 404) {
      notFound();
      return;
    }
    const usable = res.ok && isJob(res.data);
    if (usable) {
      job = res.data;
      try {
        render();
        clearProblem();
      } catch (err) {
        showProblem('This scan could not be shown', 'The page could not read the scan status. It keeps trying.');
      }
    } else {
      requestProblem(res, 'The scan status');
    }
    // Keep polling while the job runs, and keep trying while there is no usable answer.
    if (!usable || job.status === 'running') schedulePoll();
  }

  // ---- stopping --------------------------------------------------------

  async function requestStop() {
    if (stopping || gone) return;
    stopping = true;
    if (job) render();
    else renderStop(true);
    let res;
    try {
      res = await api.post('/api/scans/' + jobId + '/stop', {});
    } catch (err) {
      res = { ok: false, status: 0, data: null };
    }
    if (!alive) return;
    stopping = false;
    if (res.status === 404) {
      notFound();
      return;
    }
    if (res.ok && isJob(res.data)) {
      job = res.data;
      clearProblem();
    } else if (res.status === 0) {
      showProblem('The scan was not stopped', 'The ReconMind server is not answering. Try again when it is back.');
    } else if (res.ok) {
      showProblem('The scan may not have stopped', 'The server sent an answer the page could not read. Check the status above.');
    } else {
      showProblem('The scan was not stopped', 'The server answered with status ' + res.status + '. Try again.');
    }
    try {
      if (job) render();
      else renderStop(false);
    } catch (err) {
      renderStop(false);
    }
    // The stop did not go through and the job still runs: keep following it.
    if (job && job.status === 'running') schedulePoll();
  }

  function openStopDialog() {
    if (stopping || gone) return;
    const dialog = refs.stopDialog;
    if (dialog.open) return;
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
    refs.stopCancel.focus();
  }

  function closeStopDialog() {
    const dialog = refs.stopDialog;
    if (typeof dialog.close === 'function') dialog.close();
    else dialog.removeAttribute('open');
  }

  refs.stop.addEventListener('click', openStopDialog);
  refs.stopCancel.addEventListener('click', () => {
    closeStopDialog();
    refs.stop.focus();
  });
  refs.stopConfirm.addEventListener('click', () => {
    closeStopDialog();
    requestStop();
  });

  tickTimer = setInterval(renderElapsed, 1000);
  loadToolNames();
  poll();

  return () => {
    alive = false;
    clearTimeout(pollTimer);
    clearInterval(tickTimer);
    if (refs.stopDialog.open) closeStopDialog();
  };
}
