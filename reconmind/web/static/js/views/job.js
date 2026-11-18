/*
 * Live run (#/job/<id>), matching docs/design/screens/02_LiveRun.html.
 *
 * Two sources, both polled every second while the job runs:
 *
 *   GET /api/scans/<id>                  the job: label, status, start and
 *                                        end, run id, the technical log
 *   GET /api/scans/<id>/events?since=N   the progress events the CLI wrote
 *                                        (reconmind/core/events.py), read
 *                                        from line N on, so each poll only
 *                                        brings what is new
 *
 * From the events: the plan (target, preset, ports, checks), the open ports
 * (radar dots, DESIGN 5.12), each step's start and end (the step list, with
 * elapsed times instead of a fake percentage), the exact commands, the AI
 * analysis phase and the run id of the saved report. When the job ends one
 * last events read picks up the rest, the radar stops sweeping, and Open
 * report links to #/report/<run id>.
 *
 * Kept from step 2C: Stop asks first in an in page dialog, and the technical
 * log stays folded. Everything from the server or the target's tools is set
 * with textContent or through the CSSOM, never as markup. Every request is
 * checked: a server that does not answer or an answer that cannot be read
 * gives a calm notice and the page keeps trying. Nothing throws out of a
 * timer or a click.
 */

import * as api from '../api.js';
import { checkLive, markRunning } from '../live.js';
import {
  clone, formatDuration, h, isRunId, JOB_ID, joinList, parseTime, plural, portX, reducedMotion,
} from '../ui.js';
import { ACTION_COPY } from './newscan.js';

const POLL_MS = 1000;
const MAX_COMMANDS = 500;
const MAX_EVENT_ROUNDS = 20;
const SVG_NS = 'http://www.w3.org/2000/svg';
const RADAR_RADII = [0.44, 0.64, 0.84];
const SWEEP_SECONDS = 4;

const STATUS_WORDS = {
  running: 'Running',
  done: 'Finished',
  failed: 'Failed',
  refused: 'Refused',
  stopped: 'Stopped',
  interrupted: 'Interrupted',
};

const PRESET_TITLES = { quick: 'Quick scan', standard: 'Standard scan', full: 'Full scan' };
const ATTACK_ACTION = 'attack_map';
const CODE_ACTION = 'code';
const CODE_TOOLS = {
  semgrep: { name: 'Semgrep', tool: 'semgrep' },
  bandit: { name: 'Bandit', tool: 'bandit' },
  explanation: { name: 'AI analysis', tool: '' },
};
const HIDDEN_LOG_PREFIX = 'Loading weights';
const STEP_STATES = ['start', 'done', 'error', 'skipped'];

const SAVED = 'The scan finished and the report is saved.';

/* What each ending means and what to do next. */
function endNote(job) {
  switch (job.status) {
    case 'done':
      // A finished report without the AI summary: say so calmly, the tool results are all there.
      return typeof job.warning === 'string' && job.warning ? job.warning + ' ' + SAVED : null;
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
        + 'report, marked Stopped.';
    case 'interrupted':
      return 'The ReconMind server stopped while this scan ran, so its end was not recorded. '
        + 'Look in Targets before scanning again.';
    default:
      return null;
  }
}

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isJob = (data) => isObject(data) && typeof data.status === 'string';
const text = (v) => (typeof v === 'string' ? v : '');
const portOf = (v) => (Number.isInteger(v) && v >= 1 && v <= 65535 ? v : null);

/* A small stroke icon for the step list. */
function icon(paths, size, label) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  for (const [k, v] of Object.entries({
    width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
    'stroke-width': '3', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', role: 'img',
    'aria-label': label,
  })) svg.setAttribute(k, String(v));
  for (const d of paths) {
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

function stepIcon(state) {
  if (state === 'done') return h('span', { class: 'ic done' }, icon(['M5 12.5l4.5 4.5L19 7.5'], 14, 'Done'));
  if (state === 'run') return h('span', { class: 'ic run', role: 'img', 'aria-label': 'Running' });
  if (state === 'skip') return h('span', { class: 'ic skip' }, icon(['M6 12h12'], 12, 'Skipped'));
  if (state === 'error') return h('span', { class: 'ic err' }, icon(['M6 6l12 12M18 6L6 18'], 12, 'Failed'));
  if (state === 'notrun') return h('span', { class: 'ic skip' }, icon(['M6 12h12'], 12, 'Did not run'));
  return h('span', { class: 'ic wait', role: 'img', 'aria-label': 'Waiting' });
}

function portsPhrase(ports) {
  const list = ports.map(String);
  return (list.length === 1 ? 'port ' : 'ports ') + joinList(list);
}

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
  let shownRows = null;
  let shownBlips = null;
  let shownTips = null;
  let wasRunning = false;
  let stopping = false;
  let gone = false;
  let actionList = null; // [{id, name}] from /api/options, in run order

  // What the events have said so far.
  const ev = {
    since: 0,
    plan: null,          // {target, preset, ports, actions, mode}
    ports: null,         // [{port, service}] once nmap finished
    steps: {},           // action id to Map(tool|port to call)
    commands: [],        // [{time, text}]
    shownCommands: 0,
    analysis: null,      // time the AI analysis started
    finished: null,      // {status, run_id}
    stopped: null,       // {finished, not_run}
  };
  let rowTimes = [];     // [{el, row}] for the elapsed times

  // ---- notices ---------------------------------------------------------

  function notice(title, body, extra) {
    const { root: box, refs: r } = clone('tpl-notice');
    r.title.textContent = title || '';
    r.title.hidden = !title;
    r.text.textContent = body || '';
    if (extra) r.extra.append(extra);
    return box;
  }

  /* A problem with the requests themselves; shown once until it changes. */
  function showProblem(title, body) {
    const key = title + '|' + body;
    if (key === shownProblem) return;
    shownProblem = key;
    refs.problem.replaceChildren(notice(title, body));
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

  // ---- events ----------------------------------------------------------

  function applyEvent(e) {
    if (!isObject(e)) return;
    const time = parseTime(e.time);
    switch (e.kind) {
      case 'plan':
        ev.plan = {
          target: text(e.target),
          preset: text(e.preset),
          ports: text(e.ports),
          actions: Array.isArray(e.actions) ? e.actions.filter((a) => typeof a === 'string') : [],
          mode: text(e.mode),
        };
        break;
      case 'ports':
        if (Array.isArray(e.ports)) {
          ev.ports = e.ports.filter(isObject)
            .map((p) => ({ port: portOf(p.port), service: text(p.service) }))
            .filter((p) => p.port !== null);
        }
        break;
      case 'step': {
        const action = text(e.action);
        const tool = text(e.tool);
        if (!action || !tool || !STEP_STATES.includes(e.status)) break;
        const port = portOf(e.port);
        const calls = ev.steps[action] || (ev.steps[action] = new Map());
        const key = tool + '|' + (port === null ? '' : port);
        const call = calls.get(key) || { tool, port, start: null, end: null };
        if (e.status === 'start') {
          call.state = 'run';
          call.start = time;
        } else if (e.status === 'skipped') {
          call.state = 'skip';
          call.reason = text(e.reason);
          call.start = call.start || time;
          call.end = time;
        } else {
          call.state = e.status === 'done' ? 'done' : 'error';
          call.message = text(e.message);
          call.end = time;
          // Exploit Hunt's done event carries how many services had matches.
          if (Number.isInteger(e.count) && e.count >= 0) call.count = e.count;
        }
        calls.set(key, call);
        break;
      }
      case 'command':
        if (typeof e.command === 'string' && ev.commands.length < MAX_COMMANDS) {
          ev.commands.push({ time, text: e.command });
        }
        break;
      case 'phase':
        if (e.phase === 'analysis') ev.analysis = time || new Date();
        break;
      case 'stopped':
        ev.stopped = {
          finished: Array.isArray(e.finished) ? e.finished.map(String) : [],
          notRun: Array.isArray(e.not_run) ? e.not_run.map(String) : [],
        };
        break;
      case 'finished':
        ev.finished = { status: text(e.status), runId: isRunId(e.run_id) ? e.run_id : null };
        break;
      default:
        break;
    }
  }

  /* Read every new event; true when the events are current. */
  async function fetchEvents() {
    for (let round = 0; round < MAX_EVENT_ROUNDS; round += 1) {
      let res;
      try {
        res = await api.get('/api/scans/' + jobId + '/events?since=' + ev.since);
      } catch (err) {
        res = { ok: false, status: 0, data: null };
      }
      if (!alive) return true;
      const d = res.data;
      if (!res.ok || !isObject(d) || !Array.isArray(d.events) || !Number.isInteger(d.next)) {
        requestProblem(res, 'The scan progress');
        return false;
      }
      for (const e of d.events) applyEvent(e);
      ev.since = Math.max(ev.since, d.next);
      if (d.more !== true) return true;
    }
    return true;
  }

  // ---- the step list ---------------------------------------------------

  function loadActions() {
    api.options().then((res) => {
      if (!alive || !res.ok) return;
      actionList = res.data.actions.map((a) => ({ id: a.id, name: a.name }));
      if (job) render();
    }).catch(() => {});
  }

  const isCode = () => !!job && job.kind === 'code';
  const running = () => !!job && job.status === 'running';

  /* One row for a group of calls (all the calls of one action). */
  function rowFrom(id, name, tool, calls, waitText) {
    const list = calls ? Array.from(calls.values()) : [];
    const row = { id, name, tool, state: 'wait', sub: waitText || 'Waiting', start: null, end: null };
    if (!list.length) {
      if (!running()) {
        row.state = 'notrun';
        row.sub = 'Did not run';
      }
      return row;
    }
    row.start = list.map((c) => c.start).filter(Boolean).sort((a, b) => a - b)[0] || null;
    const active = list.filter((c) => c.state === 'run');
    const ends = list.map((c) => c.end).filter(Boolean).sort((a, b) => b - a);
    const ports = (state) => list.filter((c) => c.state === state && c.port !== null).map((c) => c.port);
    if (active.length && running()) {
      row.state = 'run';
      const where = active.filter((c) => c.port !== null).map((c) => c.port);
      row.sub = where.length ? 'On ' + portsPhrase(where) : 'Running';
      return row;
    }
    row.end = ends[0] || null;
    const errors = list.filter((c) => c.state === 'error');
    if (active.length) {
      row.state = 'notrun';
      row.sub = 'Stopped while running';
    } else if (list.every((c) => c.state === 'skip')) {
      row.state = 'skip';
      const reason = list.find((c) => c.reason);
      row.sub = reason ? 'Skipped because ' + reason.reason : 'Skipped';
    } else if (errors.length) {
      row.state = 'error';
      const message = errors.find((c) => c.message);
      row.sub = (errors.length < list.length ? errors.length + ' of ' + list.length + ' failed. ' : 'Failed. ')
        + (message ? message.message : 'Open the technical log to see why.');
    } else {
      row.state = 'done';
      const done = ports('done');
      row.sub = done.length ? 'Done on ' + portsPhrase(done) : 'Done';
    }
    return row;
  }

  function reconRows() {
    const plan = ev.plan;
    const rows = [];
    const refused = job.status === 'refused' || (ev.finished && ev.finished.status === 'refused');
    // The CLI writes the plan event only after the gate let the target through.
    const gate = { id: 'gate', name: 'Authorization gate', tool: '', start: null, end: null };
    if (refused) {
      gate.state = 'error';
      gate.sub = 'The target is not on the allowlist, so nothing was sent to it';
    } else if (plan) {
      gate.state = 'done';
      gate.sub = (plan.target || 'The target') + ' is inside an allowed lab network';
    } else {
      gate.state = running() ? 'run' : 'notrun';
      gate.sub = running() ? 'Checking the target' : 'Did not run';
    }
    rows.push(gate);
    if (refused) return rows;

    const chosen = plan ? plan.actions : [];
    const order = actionList ? actionList.map((a) => a.id) : chosen;
    const names = {};
    for (const a of actionList || []) names[a.id] = a.name;
    for (const id of order.filter((a) => chosen.includes(a))) {
      const copy = ACTION_COPY[id];
      const row = rowFrom(id, names[id] || id, copy ? copy.tool : '', ev.steps[id]);
      if (id === 'surface' && row.state === 'done' && ev.ports) {
        row.sub = plural(ev.ports.length, 'open port', 'open ports') + ' found';
      }
      if (id === 'exploits' && row.state === 'done') {
        const call = Array.from((ev.steps[id] || new Map()).values())
          .find((c) => typeof c.count === 'number');
        if (call) row.sub = 'Matches on ' + plural(call.count, 'service', 'services');
      }
      rows.push(row);
    }

    const final = rowFrom(ATTACK_ACTION, 'ATT&CK mapping and summary', '', ev.steps[ATTACK_ACTION],
      'Runs once every tool has finished');
    if (ev.analysis) {
      final.start = final.start || ev.analysis;
      if (running()) {
        final.state = 'run';
        final.sub = 'Writing the AI analysis';
      } else if (final.state !== 'error') {
        final.state = job.status === 'done' ? 'done' : final.state;
        if (job.status === 'done') final.sub = 'Done, with AI analysis';
      }
    } else if (final.state === 'done' && ev.plan && ev.plan.mode === 'standard') {
      final.sub = 'Done. AI analysis was off for this scan';
    }
    rows.push(final);
    return rows;
  }

  function codeRows() {
    const calls = ev.steps[CODE_ACTION] || new Map();
    const byTool = {};
    for (const [key, call] of calls) byTool[call.tool] = new Map([[key, call]]);
    const tools = ['semgrep', 'bandit'];
    if (byTool.explanation) tools.push('explanation');
    return tools.map((tool) => {
      const copy = CODE_TOOLS[tool];
      return rowFrom(tool, copy.name, copy.tool, byTool[tool]);
    });
  }

  function rows() {
    return isCode() ? codeRows() : reconRows();
  }

  function rowTime(row) {
    if (!row.start) return '';
    const end = row.end || (row.state === 'run' ? new Date() : null);
    return end ? formatDuration((end - row.start) / 1000) : '';
  }

  function renderRows(list) {
    const key = JSON.stringify(list.map((r) => [r.id, r.state, r.sub, r.name]));
    if (key !== shownRows) {
      shownRows = key;
      rowTimes = [];
      refs.steps.replaceChildren(...list.map((row) => {
        const time = h('span', { class: 'time num' });
        rowTimes.push({ el: time, row });
        return h('div', { class: 'step ' + row.state },
          stepIcon(row.state),
          h('div', { class: 'step-text' },
            h('span', { class: 'nm', text: row.name }),
            row.tool ? h('span', { class: 'tool', text: row.tool }) : null,
            h('div', { class: 'sub', text: row.sub }),
            row.state === 'run' ? h('div', { class: 'indet', 'aria-hidden': 'true' }) : null),
          time);
      }));
    }
    for (const { el, row } of rowTimes) {
      const value = rowTime(row);
      if (el.textContent !== value) el.textContent = value;
    }
  }

  // ---- the head: state, title, progress, counts ------------------------

  function elapsedSeconds() {
    const started = parseTime(job.started);
    if (!started) return null;
    const end = parseTime(job.finished) || new Date();
    return (end - started) / 1000;
  }

  function renderState() {
    if (!job) return;
    const seconds = elapsedSeconds();
    const isRunning = running();
    let value;
    if (isRunning) value = 'Running' + (seconds === null ? '' : ' for ' + formatDuration(seconds));
    else {
      value = (STATUS_WORDS[job.status] || 'Ended')
        + (seconds === null ? '' : ' after ' + formatDuration(seconds));
    }
    if (refs.stateText.textContent !== value) refs.stateText.textContent = value;
    refs.state.className = 'live-state ' + (isRunning ? 'on' : job.status);
    refs.stateDot.hidden = !isRunning;
    for (const { el, row } of rowTimes) {
      const t = rowTime(row);
      if (el.textContent !== t) el.textContent = t;
    }
  }

  function labelParts() {
    const label = typeof job.label === 'string' && job.label ? job.label : 'Scan';
    const comma = label.indexOf(', ');
    return comma > 0 ? [label.slice(0, comma), label.slice(comma + 2)] : [label, ''];
  }

  function subtitle() {
    const [kind] = labelParts();
    if (isCode()) {
      return 'Code scan with Semgrep and Bandit. The code is read, never run.';
    }
    const plan = ev.plan;
    if (!plan) return kind + '.';
    const title = PRESET_TITLES[plan.preset] && !kind.startsWith('Custom') ? PRESET_TITLES[plan.preset] : kind;
    let ports;
    if (plan.ports === 'top') ports = 'the top 1000 TCP ports';
    else if (plan.ports === 'all') ports = 'all 65535 TCP ports';
    else ports = 'TCP ports ' + plan.ports;
    const total = actionList ? actionList.length : null;
    const n = plan.actions.length;
    const checks = total && n === total ? 'all ' + total + ' checks'
      : (total ? n + ' of ' + total + ' checks' : plural(n, 'check', 'checks'));
    const ai = plan.mode === 'ai' ? ' AI analysis on.' : (plan.mode === 'standard' ? ' AI analysis off.' : '');
    return title + ' on ' + ports + ' with ' + checks + '.' + ai;
  }

  function renderHead(list) {
    const [kind, target] = labelParts();
    const title = (ev.plan && ev.plan.target) || target || kind;
    refs.label.textContent = title;
    document.title = (target ? kind + ', ' + target : kind) + ' | ReconMind';
    refs.sub.textContent = subtitle();

    const steps = list.filter((r) => r.id !== 'gate');
    const ended = steps.filter((r) => ['done', 'skip', 'error', 'notrun'].includes(r.state)).length;
    const now = steps.find((r) => r.state === 'run');
    const isRunning = running();
    refs.progress.hidden = !isRunning || !steps.length;
    if (isRunning) {
      const gateRow = list.find((r) => r.id === 'gate');
      let line;
      if (now) line = (now.id === ATTACK_ACTION && ev.analysis ? 'Now writing the AI analysis'
        : 'Now running ' + now.name + (now.sub.startsWith('On ') ? ' on ' + now.sub.slice(3) : ''));
      else if (gateRow && gateRow.state === 'run') line = 'Checking the target against the allowlist';
      else line = 'Waiting for the next step';
      refs.step.textContent = line;
      refs.stepCount.textContent = ended + ' of ' + steps.length + ' steps';
      // The share of steps that ended: a count of real steps, not a guess of time.
      refs.progBar.style.transform = 'scaleX(' + (steps.length ? ended / steps.length : 0).toFixed(3) + ')';
    }

    refs.nPorts.textContent = String(ev.ports ? ev.ports.length : 0);
    const finished = steps.filter((r) => r.state === 'done' || r.state === 'error').length;
    refs.nChecks.textContent = String(finished);
    refs.nChecksLabel.textContent = isCode() ? 'tools finished' : 'steps finished';
    refs.nCommands.textContent = String(ev.commands.length);
  }

  // ---- radar, tips, commands, report link ------------------------------

  function renderRadar() {
    const ports = ev.ports || [];
    const isRunning = running();
    refs.sweep.hidden = !isRunning || reducedMotion();
    refs.radar.classList.toggle('still', !isRunning);
    const key = ports.map((p) => p.port).join(',');
    if (key === shownBlips) return;
    shownBlips = key;
    refs.radar.setAttribute('aria-label', ports.length
      ? 'Radar showing ' + plural(ports.length, 'open port', 'open ports') + ': ' + joinList(ports.map((p) => p.port))
      : 'Radar with no open ports found yet');
    refs.blips.replaceChildren(...ports.map((p, i) => {
      const frac = portX(p.port) / 100;
      const angle = frac * Math.PI * 2;
      const r = RADAR_RADII[i % RADAR_RADII.length] * 50;
      const dot = h('span', { class: 'blip', title: p.port + (p.service ? ' ' + p.service : '') });
      dot.style.left = (50 + r * Math.sin(angle)).toFixed(2) + '%';
      dot.style.top = (50 - r * Math.cos(angle)).toFixed(2) + '%';
      // The dot flashes exactly when the beam passes over it.
      dot.style.animationDelay = (frac * SWEEP_SECONDS).toFixed(2) + 's';
      return dot;
    }));
  }

  function renderTips() {
    const cves = !!(ev.plan && ev.plan.actions.includes('cves'));
    const key = cves + '|' + isCode();
    if (key === shownTips) return;
    shownTips = key;
    const tips = [];
    if (cves) tips.push('NVD answers are kept for 24 hours, so scanning this target again will be faster.');
    tips.push('You can open other screens while the scan runs. The report lands in the target\'s folder when it finishes.');
    if (isCode()) tips.push('Only the flagged lines are ever sent to the AI model, never whole files.');
    refs.tips.replaceChildren(...tips.map((t) => h('p', { class: 'tip', text: t })));
  }

  function renderCommands() {
    const box = refs.commands;
    if (ev.shownCommands === 0 && !ev.commands.length) {
      if (!box.childElementCount) box.append(h('div', { class: 'cmdline empty', text: 'No command has run yet.' }));
      return;
    }
    if (ev.shownCommands === 0) box.replaceChildren();
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 24;
    for (const prev of box.querySelectorAll('.cmdline.latest')) prev.classList.remove('latest');
    for (let i = ev.shownCommands; i < ev.commands.length; i += 1) {
      const c = ev.commands[i];
      const stamp = c.time ? [c.time.getHours(), c.time.getMinutes(), c.time.getSeconds()]
        .map((n) => String(n).padStart(2, '0')).join(':') : '';
      box.append(h('div', { class: 'cmdline' }, h('span', { class: 'cmdtime', text: stamp }), c.text));
    }
    ev.shownCommands = ev.commands.length;
    const last = box.lastElementChild;
    if (last && running()) last.classList.add('latest');
    if (atBottom) box.scrollTop = box.scrollHeight;
  }

  function runId() {
    if (isRunId(job.run_id)) return job.run_id;
    return ev.finished && ev.finished.runId ? ev.finished.runId : null;
  }

  function renderReport() {
    const isRunning = running();
    const id = isRunning ? null : runId();
    const href = id ? '#/report/' + encodeURIComponent(id) : null;
    // One Open report button, in the header. The Report card only says
    // whether a report is saved, as in 02_LiveRun.html.
    refs.openReport.hidden = !href;
    if (href) refs.openReport.setAttribute('href', href);
    else refs.openReport.removeAttribute('href');
    refs.skels.hidden = !isRunning;
    refs.background.hidden = !isRunning;
    refs.another.hidden = isRunning;
    if (isRunning) refs.reportText.textContent = 'Written when the steps finish.';
    else if (id) refs.reportText.textContent = job.status === 'stopped' ? 'A partial report is saved.' : 'The report is saved.';
    else refs.reportText.textContent = 'No report was saved for this scan.';
  }

  // ---- rendering -------------------------------------------------------

  function renderStop(isRunning) {
    refs.stop.hidden = !(isRunning || stopping);
    refs.stop.disabled = stopping;
    refs.stop.setAttribute('aria-busy', stopping ? 'true' : 'false');
    refs.stopSpinner.hidden = !stopping;
    refs.stopLabel.textContent = stopping ? 'Stopping' : 'Stop scan';
    if (!isRunning && refs.stopDialog.open) refs.stopDialog.close();
  }

  function renderNote() {
    // While a stop is in flight the partial report is still being saved: wait for it.
    let body = stopping ? null : endNote(job);
    if (!stopping && job.status === 'stopped' && ev.stopped && ev.stopped.notRun.length) {
      body = (body || '') + ' Did not run: ' + ev.stopped.notRun.join(', ') + '.';
    }
    const key = body ? job.status + '|' + body : null;
    if (key === shownEnd) return;
    shownEnd = key;
    refs.alert.replaceChildren();
    if (body) refs.alert.append(notice(null, body));
  }

  function renderLog() {
    const lines = Array.isArray(job.lines) ? job.lines.map(String) : [];
    const value = lines.filter((line) => !line.startsWith(HIDDEN_LOG_PREFIX)).join('\n');
    if (value === shownOutput) return;
    const out = refs.out;
    // Follow new lines only when the reader is already at the bottom.
    const atBottom = out.scrollTop + out.clientHeight >= out.scrollHeight - 24;
    out.textContent = value;
    if (atBottom) out.scrollTop = out.scrollHeight;
    shownOutput = value;
  }

  function render() {
    const isRunning = running();
    renderStop(isRunning);
    // This page may show an older job while another one runs, so a job that
    // is not running asks the server instead of turning the dot off.
    if (isRunning) markRunning();
    else if (wasRunning) checkLive();
    wasRunning = isRunning;

    const list = rows();
    renderHead(list);
    renderRows(list);
    renderState();
    renderRadar();
    renderTips();
    renderCommands();
    renderReport();
    renderLog();
    renderNote();
  }

  function notFound() {
    gone = true;
    clearTimeout(pollTimer);
    if (refs.stopDialog.open) refs.stopDialog.close();
    refs.label.textContent = 'Scan not found';
    document.title = 'Scan not found | ReconMind';
    refs.stateText.textContent = 'Unknown scan';
    refs.stateDot.hidden = true;
    refs.sub.textContent = '';
    refs.stop.hidden = true;
    refs.progress.hidden = true;
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
    if (!alive || gone) {
      pollPending = false;
      return;
    }
    if (res.status === 404) {
      pollPending = false;
      notFound();
      return;
    }
    const usable = res.ok && isJob(res.data);
    let eventsOk = true;
    if (usable) {
      job = res.data;
      // Read the events after the status, so a job that just ended has written all of its own.
      eventsOk = await fetchEvents();
      if (!alive) return;
      try {
        render();
        if (eventsOk) clearProblem();
      } catch (err) {
        showProblem('This scan could not be shown', 'The page could not read the scan status. It keeps trying.');
      }
    } else {
      requestProblem(res, 'The scan status');
    }
    pollPending = false;
    // Keep polling while the job runs, and keep trying while an answer was missing.
    if (!usable || !eventsOk || job.status === 'running') schedulePoll();
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
    // Pick up the last events and the final status, whichever way the stop went.
    schedulePoll();
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

  tickTimer = setInterval(() => {
    try {
      renderState();
    } catch (err) {
      // a tick never throws
    }
  }, 1000);
  // A link with an id no job can have is answered here, not sent to the server.
  if (JOB_ID.test(jobId)) {
    loadActions();
    poll();
  } else {
    notFound();
  }

  return () => {
    alive = false;
    clearTimeout(pollTimer);
    clearInterval(tickTimer);
    if (refs.stopDialog.open) closeStopDialog();
  };
}
