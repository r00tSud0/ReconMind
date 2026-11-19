/*
 * MORVAIN-X0 panel on the Live run page (artboard 11, "MORVAIN-X0 agent").
 *
 * Built from the job's "agent" events: the character with its state, the
 * conversation, and the plan card the operator answers. Answers go to
 * POST /api/scans/<id>/agent and only say which proposed checks to run,
 * to redirect with a message, or to finish. The agent itself runs in the
 * scan's own process, inside the authorization gate.
 *
 * Nothing from the events is parsed as HTML: every node is built with h().
 */
import * as api from '../api.js';
import { h } from '../ui.js';
import { createMorvain } from '../morvain_gl.js';

const isObject = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const text = (x) => (typeof x === 'string' ? x : '');

const STATES = {
  ready: ['Ready', 'Give it one lab target and it maps the surface first.'],
  thinking: ['Thinking', 'Working out the next move from what it found.'],
  running: ['Running a check', 'Executing an approved step against the target.'],
  awaiting: ['Waiting for your approval', 'It will not act until you approve.'],
  error: ['A problem came up', 'It tells you what happened and offers a way on.'],
  done: ['Writing the report', 'The tools are done. The report comes next.'],
  finished: ['Finished', 'The session is over. Its report is saved: Open report is in the progress panel.'],
  stopped: ['Stopped', 'The session was stopped. What it found is saved.'],
};
// The character: the approved portrait, alive (see ../morvain_gl.js).
// States where the agent is working, so its red lights are on.
const POWERED = new Set(['thinking', 'running', 'awaiting', 'done', 'error']);

function warnIcon() {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  for (const [k, v] of Object.entries({ width: '20', height: '20', viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'aria-hidden': 'true' })) {
    svg.setAttribute(k, v);
  }
  for (const d of ['M12 3l9.5 17h-19z', 'M12 10v4M12 17v.01']) {
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  svg.setAttribute('class', 'agent-warn-icon');
  return svg;
}

export function createAgentPanel(jobId) {
  const entries = [];          // agent events in order
  let target = '';
  let jobState = 'running';    // running, or the job's end status
  let sending = false;
  let answered = null;         // the plan entry this page already answered
  let redirectOpen = false;
  let feedback = '';
  let lastKey = '';
  let shownCount = 0;
  let intro = null;            // shown in the chat before a session starts
  let scrolledOnce = false;

  // ---- the character ----------------------------------------------------
  // One surface that bends (a mesh warp), so the head, neck and chest move
  // together like one body. Without WebGL it falls back to a still portrait
  // whose lights fade on and off.
  const missing = h('div', { class: 'agent-portrait-missing', hidden: true },
    h('span', { text: 'MORVAIN-X0' }),
    h('span', { class: 'tag', text: 'Portrait file missing: static/img/morvain-x0.png' }));
  const stage = h('div', { class: 'mx-stage', role: 'img',
    'aria-label': 'MORVAIN-X0, a black chrome robotic face with red optics' });
  const body = createMorvain(stage, () => {
    stage.hidden = true;
    missing.hidden = false;
    character.classList.add('no-portrait');
  });
  let shownState = '';
  const statusText = h('span', { text: '' });
  const subText = h('p', { class: 'tag agent-sub' });
  const character = h('section', { class: 'glass agent-char', 'aria-label': 'MORVAIN-X0 status' },
    h('span', { class: 'agent-badge', text: 'MORVAIN-X0' }),
    h('div', { class: 'agent-core' },
      h('div', { class: 'agent-corewrap' }, stage, missing)),
    h('div', { class: 'agent-status', role: 'status', 'aria-live': 'polite' },
      h('span', { class: 'agent-dot', 'aria-hidden': 'true' }), statusText),
    subText,
    h('div', { class: 'agent-rule' }),
    h('p', { class: 'tag agent-scope', text: 'MORVAIN-X0 can only use the 8 checks on this one '
      + 'target. Anything outside the lab networks is refused by the gate, no matter what you ask.' }));

  // ---- the conversation -------------------------------------------------
  const title = h('h2', { class: 'agent-title', text: 'Agent scan' });
  const thread = h('div', { class: 'agent-thread', 'aria-live': 'polite' });
  const chat = h('section', { class: 'glass agent-chat' },
    h('div', { class: 'agent-chat-head' },
      h('div', { class: 'agent-chat-id' }, title,
        h('span', { class: 'tag', text: 'MORVAIN-X0 investigates with you. It asks before each move.' }))),
    thread);
  const el = h('div', { class: 'agent-wrap reveal' }, character, chat);

  function pending() {
    const last = entries[entries.length - 1];
    if (!last || jobState !== 'running') return null;
    return last.from === 'agent' && last.state === 'awaiting' && last !== answered ? last : null;
  }

  async function send(entry, decision, actions, message) {
    const round = Number(entry.round) || 0;
    if (sending) return;
    sending = true;
    feedback = 'Sending your answer.';
    render();
    let res;
    try {
      res = await api.post('/api/scans/' + encodeURIComponent(jobId) + '/agent',
        { round, decision, actions, message });
    } catch (err) {
      res = { ok: false, data: null };
    }
    sending = false;
    if (res.ok) {
      answered = entry;
      redirectOpen = false;
      feedback = '';
    } else {
      feedback = res.data && res.data.message ? String(res.data.message)
        : 'Your answer could not be sent. Try again.';
    }
    render();
  }

  /* An answered plan shows what happened to each step, not checkboxes. */
  function outcome(answer, action) {
    if (!answer) return 'Not answered';
    if (answer.decision === 'approve') {
      return (answer.actions || []).includes(action) ? 'Approved' : 'Skipped';
    }
    return answer.decision === 'redirect' ? 'Replaced after your redirect' : 'Not run';
  }

  function planCard(entry, live, answer) {
    const steps = Array.isArray(entry.plan) ? entry.plan.filter(isObject) : [];
    const boxes = [];
    if (!live) {
      return h('div', { class: 'agent-plan answered' },
        h('h4', { text: entry.source === 'rules' ? 'Proposed plan (from fixed rules)' : 'Proposed plan' }),
        h('ol', {}, ...steps.map((s) => {
          const result = outcome(answer, text(s.action));
          return h('li', { class: 'agent-step' },
            h('div', { class: 'agent-step-row' },
              h('span', { class: 'agent-step-text' },
                h('strong', { text: text(s.name) }),
                h('span', { class: 'agent-why', text: text(s.why) })),
              h('span', { class: 'agent-outcome' + (result === 'Approved' ? ' yes' : ''), text: result })));
        })));
    }
    const items = steps.map((s) => {
      const box = h('input', { type: 'checkbox', checked: true, disabled: !live || sending,
        'aria-label': 'Run ' + text(s.name) });
      box.dataset.action = text(s.action);
      boxes.push(box);
      return h('li', { class: 'agent-step' },
        h('label', { class: 'agent-step-row' }, box,
          h('span', { class: 'agent-step-text' },
            h('strong', { text: text(s.name) }),
            h('span', { class: 'agent-why', text: text(s.why) }))));
    });
    const card = h('div', { class: 'agent-plan' + (live ? '' : ' answered') },
      h('h4', { text: entry.source === 'rules' ? 'Proposed plan (from fixed rules)' : 'Proposed plan' }),
      h('ol', {}, ...items));
    if (!live) return card;
    card.append(h('p', { class: 'tag agent-hint', text: 'Untick a step to skip it.' }));
    const approve = h('button', { type: 'button', class: 'btn primary sm', text: 'Approve plan',
      disabled: sending });
    approve.addEventListener('click', () => send(entry, 'approve',
      boxes.filter((b) => b.checked).map((b) => b.dataset.action), ''));
    const redirect = h('button', { type: 'button', class: 'btn quiet sm', text: 'Let me redirect',
      disabled: sending, 'aria-expanded': redirectOpen ? 'true' : 'false' });
    redirect.addEventListener('click', () => { redirectOpen = !redirectOpen; render(); });
    const finish = h('button', { type: 'button', class: 'btn quiet sm',
      text: 'Finish with what we have', disabled: sending });
    finish.addEventListener('click', () => send(entry, 'finish', [], ''));
    card.append(h('div', { class: 'agent-buttons' }, approve, redirect, finish));
    if (redirectOpen) {
      const field = h('textarea', { class: 'field agent-field', rows: '2', maxlength: '500',
        id: 'agent-redirect', placeholder: 'For example: do the web servers first, skip SMB' });
      const go = h('button', { type: 'button', class: 'btn primary sm', text: 'Send', disabled: sending });
      go.addEventListener('click', () => {
        const message = field.value.trim();
        if (message) send(entry, 'redirect', [], message);
        else field.focus();
      });
      card.append(h('div', { class: 'agent-redirect' },
        h('label', { class: 'label', for: 'agent-redirect', text: 'Tell MORVAIN-X0 what to change' }),
        field, go));
      setTimeout(() => field.focus(), 0);
    }
    if (feedback) card.append(h('p', { class: 'help agent-feedback', role: 'status', text: feedback }));
    return card;
  }

  function bubble(entry, live, answer) {
    if (entry.from === 'operator') {
      return h('div', { class: 'agent-msg me' },
        h('span', { class: 'agent-av me', text: 'YOU' }),
        h('div', { class: 'agent-bubble me', text: text(entry.text) }));
    }
    const parts = [h('div', { class: 'agent-who', text: 'MORVAIN-X0' })];
    if (entry.state === 'error') {
      parts.push(h('div', { class: 'agent-err' }, warnIcon(),
        h('div', {}, h('div', { class: 'agent-err-title', text: 'Heads up, a check failed' }),
          h('span', { text: text(entry.text) }))));
    } else {
      parts.push(h('span', { text: text(entry.text) }));
    }
    if (entry.state === 'awaiting') parts.push(planCard(entry, live, answer));
    return h('div', { class: 'agent-msg' },
      h('span', { class: 'agent-av x', text: 'X0' }),
      h('div', { class: 'agent-bubble x' }, ...parts));
  }

  function currentState() {
    if (jobState === 'ready') return 'ready';
    if (jobState === 'stopped') return 'stopped';
    if (jobState !== 'running') return 'finished';
    const last = [...entries].reverse().find((e) => e.from === 'agent');
    if (!last) return 'thinking';
    if (last.state === 'awaiting' && last === answered) return 'thinking';
    return STATES[last.state] ? last.state : 'thinking';
  }

  function render() {
    const state = currentState();
    const live = pending();
    const key = [entries.length, state, live ? live.round : '', sending, redirectOpen, feedback,
      target, intro ? 1 : 0].join('|');
    if (key === lastKey) return;
    lastKey = key;
    const powered = POWERED.has(state);
    // A session that has only just begun powers up from off, even when this
    // panel is new (the MORVAIN-X0 tab swaps its idle panel for the session).
    const agentLines = entries.filter((e) => e.from === 'agent').length;
    if (shownState === '' && jobState === 'running' && agentLines <= 1) shownState = 'ready';
    const wasPowered = POWERED.has(shownState);
    character.className = 'glass agent-char state-' + state + (powered ? ' powered' : '')
      + ' mx-' + body.kind + (missing.hidden ? '' : ' no-portrait');
    // Powering up: the lights come on with a flicker and a puff of steam.
    // Finishing the work: one more puff as it cools down. Neither loops.
    // Opening the page partway through just shows the current state.
    if (shownState !== '') {
      if (powered && !wasPowered) body.steam();
      else if (state === 'done' && shownState !== 'done') body.steam();
    }
    body.setState(state);
    shownState = state;
    statusText.textContent = STATES[state][0];
    subText.textContent = STATES[state][1];
    if (!intro || entries.length) title.textContent = target ? 'Agent scan of ' + target : 'Agent scan';
    const keepField = redirectOpen ? thread.querySelector('#agent-redirect') : null;
    const draft = keepField ? keepField.value : '';
    const nearBottom = thread.scrollHeight - thread.scrollTop - thread.clientHeight < 80;
    const grew = entries.length !== shownCount;
    shownCount = entries.length;
    if (!entries.length && intro) {
      thread.replaceChildren(intro);
      return;
    }
    thread.replaceChildren(...entries.map((e, i) => bubble(e, e === live,
      entries.slice(i + 1).find((x) => x.from === 'operator'))));
    // Follow the conversation, unless the operator scrolled up to read.
    if (grew && (nearBottom || !scrolledOnce)) thread.scrollTop = thread.scrollHeight;
    scrolledOnce = true;
    const field = thread.querySelector('#agent-redirect');
    if (field && draft) field.value = draft;
  }

  return {
    el,
    apply(e) {
      if (!isObject(e)) return;
      if (e.kind === 'plan' && typeof e.target === 'string') target = e.target;
      if (e.kind !== 'agent') return;
      if (e.from !== 'agent' && e.from !== 'operator') return;
      entries.push({
        from: e.from, state: text(e.state), text: text(e.text), round: e.round,
        plan: e.plan, source: text(e.source), decision: text(e.decision),
        actions: Array.isArray(e.actions) ? e.actions.filter((a) => typeof a === 'string') : [],
      });
    },
    setJob(status) { jobState = status || 'running'; },
    setIntro(node) { intro = node; lastKey = ''; },
    setTitle(text) { title.textContent = text; },
    target: () => target,
    character,
    chat,
    render,
  };
}
