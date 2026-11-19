/*
 * MORVAIN-X0 panel on the Live run page (artboard 11, "MORVAIN-X0 agent").
 *
 * Built from the job's "agent" events: the character with its state, the
 * conversation, and the plan card the operator answers. Answers go to
 * POST /api/scans/<id>/agent and only say which proposed checks to run,
 * to redirect with a message, or to finish. The agent itself runs in the
 * scan's own process, inside the authorization gate.
 *
 * At a checkpoint the operator can also ask questions (the dock under the
 * conversation, or Tell me more on a step). Answers come from the results
 * and the plan only; asking never runs or changes anything, and the plan
 * stays open. After the session, the same dock asks about the saved report
 * (POST /api/reports/<run id>/ask).
 *
 * Nothing from the events is parsed as HTML: every node is built with h().
 */
import * as api from '../api.js';
import { h, markdownNodes } from '../ui.js';
import { createMorvain } from '../morvain_loops.js';

const isObject = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const text = (x) => (typeof x === 'string' ? x : '');

const STATES = {
  ready: ['Ready', 'Give it one lab target and it maps the surface first.'],
  thinking: ['Thinking', 'Working out the next move from what it found.'],
  running: ['Running a check', 'Executing an approved step against the target.'],
  awaiting: ['Waiting for your approval', 'It will not act until you approve. Ask it anything about the results.'],
  answering: ['Answering your question', 'The plan waits. Nothing runs while it answers.'],
  error: ['A problem came up', 'It tells you what happened and offers a way on.'],
  done: ['Writing the report', 'The tools are done. The report comes next.'],
  finished: ['Finished', 'The session is over and its report is saved. Ask about it below, or use Open report.'],
  stopped: ['Stopped', 'The session was stopped. What it found is saved.'],
};
// The character: the approved portrait, alive (see ../morvain_loops.js).
// States where the agent is working, so its lights are on: red while it
// works (with steam), yellow with sparks while it answers a question.
const POWERED = new Set(['thinking', 'running', 'awaiting', 'answering', 'done', 'error']);
const MD = { paragraph: 'agent-md', list: 'agent-md-list', heading: 'agent-md' };

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
  let asking = false;          // a checkpoint question is waiting for its answer
  let askBase = 0;             // entries.length when it was sent
  let skips = new Set();       // steps unticked on the live plan
  let skipsFor = null;         // the plan entry skips belong to
  let runId = '';              // the saved report, once the session is over
  const after = [];            // questions about the saved report: {q, a, bad}
  let afterBusy = false;
  // ---- the character ----------------------------------------------------
  // Three animation loops rendered ahead of time from the portrait (off,
  // working, answering), played as animated images, so it moves the same in
  // every browser and in the desktop window, with no WebGL needed.
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
  const dock = h('div', { class: 'agent-dock', hidden: true });
  chat.append(dock);
  const el = h('div', { class: 'agent-wrap reveal' }, character, chat);

  const isQA = (e) => (e.from === 'operator' && e.decision === 'ask')
    || (e.from === 'agent' && e.state === 'answer');

  /* The plan waiting for an answer: the last plan, with only questions and
     answers after it. */
  function pending() {
    if (jobState !== 'running') return null;
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      const e = entries[i];
      if (isQA(e)) continue;
      return e.from === 'agent' && e.state === 'awaiting' && e !== answered ? e : null;
    }
    return null;
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
    if (res.ok && decision === 'ask') {
      asking = true;
      askBase = entries.length;
      feedback = '';
    } else if (res.ok) {
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

  /* The riskiest things found so far, from the tool results by fixed rules. */
  function briefBox(entry) {
    const b = isObject(entry.brief) ? entry.brief : null;
    if (!b) return null;
    const items = Array.isArray(b.items) ? b.items.filter(isObject) : [];
    const more = Number.isInteger(b.more) && b.more > 0 ? b.more : 0;
    return h('div', { class: 'agent-brief' },
      h('h4', { text: 'What I found so far' }),
      items.length
        ? h('ul', {}, ...items.map((i) => h('li', {},
          text(i.severity) ? h('span', { class: 'sev-chip sev-' + text(i.severity), text: text(i.severity) }) : null,
          h('span', { text: text(i.text) }))))
        : h('p', { class: 'tag', text: 'Nothing high risk yet. The plan below looks deeper.' }),
      more ? h('p', { class: 'tag', text: 'And ' + more + ' more in the report.' }) : null);
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
    if (skipsFor !== entry) { skips = new Set(); skipsFor = entry; }
    const busy = sending || asking;
    const items = steps.map((s) => {
      const action = text(s.action);
      const box = h('input', { type: 'checkbox', checked: !skips.has(action), disabled: busy,
        'aria-label': 'Run ' + text(s.name) });
      box.addEventListener('change', () => {
        if (box.checked) skips.delete(action); else skips.add(action);
      });
      boxes.push(box);
      const more = h('button', { type: 'button', class: 'agent-more', text: 'Tell me more',
        disabled: busy, 'aria-label': 'Tell me more about ' + text(s.name) });
      more.addEventListener('click', () => send(entry, 'ask', [action], ''));
      return h('li', { class: 'agent-step' },
        h('div', { class: 'agent-step-line' },
          h('label', { class: 'agent-step-row' }, box,
            h('span', { class: 'agent-step-text' },
              h('strong', { text: text(s.name) }),
              h('span', { class: 'agent-why', text: text(s.why) }))),
          more));
    });
    return h('div', { class: 'agent-plan' },
      h('h4', { text: entry.source === 'rules' ? 'Proposed plan (from fixed rules)' : 'Proposed plan' }),
      h('ol', {}, ...items),
      h('p', { class: 'tag agent-hint', text: 'Untick a step to skip it. Your answer goes in the box below.' }));
  }

  /* Under the conversation: at a checkpoint, the question box and the
     plan's buttons; after the session, questions about the saved report. */
  function renderDock(live) {
    const old = dock.querySelector('#agent-ask');
    const draft = old ? old.value : '';
    const hadFocus = !!old && document.activeElement === old;
    const oldRedirect = dock.querySelector('#agent-redirect');
    const redirectDraft = oldRedirect ? oldRedirect.value : '';
    if (live) {
      dock.hidden = false;
      const busy = sending || asking;
      const field = h('input', { id: 'agent-ask', class: 'field agent-ask-field', type: 'text',
        maxlength: '500', autocomplete: 'off', disabled: busy,
        placeholder: 'Ask about the results or the plan, like: why is port 21 risky?' });
      field.value = draft;
      const askBtn = h('button', { type: 'button', class: 'btn quiet sm',
        text: asking ? 'Answering…' : 'Ask', disabled: busy });
      const ask = () => {
        const q = field.value.trim();
        if (!q) { field.focus(); return; }
        field.value = '';
        send(live, 'ask', [], q);
      };
      askBtn.addEventListener('click', ask);
      field.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); ask(); } });
      const approve = h('button', { type: 'button', class: 'btn primary sm', text: 'Approve plan', disabled: busy });
      approve.addEventListener('click', () => {
        const steps = Array.isArray(live.plan) ? live.plan.filter(isObject) : [];
        send(live, 'approve', steps.map((s) => text(s.action)).filter((a) => a && !skips.has(a)), '');
      });
      const redirect = h('button', { type: 'button', class: 'btn quiet sm', text: 'Let me redirect',
        disabled: busy, 'aria-expanded': redirectOpen ? 'true' : 'false' });
      redirect.addEventListener('click', () => { redirectOpen = !redirectOpen; render(true); });
      const finish = h('button', { type: 'button', class: 'btn quiet sm',
        text: 'Finish with what we have', disabled: busy });
      finish.addEventListener('click', () => send(live, 'finish', [], ''));
      const parts = [
        h('label', { class: 'label', for: 'agent-ask', text: 'Ask MORVAIN-X0' }),
        h('div', { class: 'agent-ask-row' }, field, askBtn),
        h('p', { class: 'tag', text: asking ? 'MORVAIN-X0 is answering. The plan waits; nothing runs.'
          : 'Asking never runs or changes anything. Up to 10 questions per plan.' }),
        h('div', { class: 'agent-buttons' }, approve, redirect, finish)];
      if (redirectOpen) {
        const rf = h('textarea', { class: 'field agent-field', rows: '2', maxlength: '500',
          id: 'agent-redirect', placeholder: 'For example: do the web servers first, skip SMB' });
        rf.value = redirectDraft;
        const go = h('button', { type: 'button', class: 'btn primary sm', text: 'Send', disabled: busy });
        go.addEventListener('click', () => {
          const message = rf.value.trim();
          if (message) send(live, 'redirect', [], message);
          else rf.focus();
        });
        parts.push(h('div', { class: 'agent-redirect' },
          h('label', { class: 'label', for: 'agent-redirect', text: 'Tell MORVAIN-X0 what to change' }),
          rf, go));
        if (!oldRedirect) setTimeout(() => rf.focus(), 0);
      }
      if (feedback) parts.push(h('p', { class: 'help agent-feedback', role: 'status', text: feedback }));
      dock.replaceChildren(...parts);
      if (hadFocus && !busy) field.focus();
      return;
    }
    if (runId && jobState !== 'running' && jobState !== 'ready') {
      dock.hidden = false;
      const field = h('input', { id: 'agent-ask', class: 'field agent-ask-field', type: 'text',
        maxlength: '1000', autocomplete: 'off', disabled: afterBusy,
        placeholder: 'Ask about the finished report, like: what should I fix first?' });
      field.value = draft;
      const askBtn = h('button', { type: 'button', class: 'btn quiet sm',
        text: afterBusy ? 'Reading…' : 'Ask', disabled: afterBusy });
      const ask = () => {
        const q = field.value.trim();
        if (!q) { field.focus(); return; }
        field.value = '';
        askReport(q);
      };
      askBtn.addEventListener('click', ask);
      field.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); ask(); } });
      dock.replaceChildren(
        h('label', { class: 'label', for: 'agent-ask', text: 'Keep asking MORVAIN-X0' }),
        h('div', { class: 'agent-ask-row' }, field, askBtn),
        h('p', { class: 'tag', text: 'Answers come only from the saved report. Nothing runs.' }));
      if (hadFocus && !afterBusy) field.focus();
      return;
    }
    dock.hidden = true;
    dock.replaceChildren();
  }

  async function askReport(question) {
    if (afterBusy || !runId) return;
    const turn = { q: question, a: '', bad: false };
    after.push(turn);
    afterBusy = true;
    render(true);
    let res;
    try {
      res = await api.post('/api/reports/' + encodeURIComponent(runId) + '/ask',
        { question, turns: after.filter((t) => t.a && !t.bad).slice(-6).map((t) => ({ q: t.q, a: t.a })) });
    } catch (err) {
      res = { ok: false, data: null };
    }
    afterBusy = false;
    if (res.ok && isObject(res.data) && typeof res.data.answer === 'string') {
      turn.a = res.data.answer;
    } else {
      turn.bad = true;
      turn.a = isObject(res.data) && typeof res.data.message === 'string'
        ? res.data.message : 'No answer came back. Try again.';
    }
    render(true);
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
    } else if (entry.state === 'answer') {
      parts.push(...markdownNodes(text(entry.text), MD));
    } else {
      parts.push(h('span', { text: text(entry.text) }));
    }
    if (entry.state === 'awaiting') {
      const box = briefBox(entry);
      if (box) parts.push(box);
      parts.push(planCard(entry, live, answer));
    }
    return h('div', { class: 'agent-msg' + (entry.state === 'answer' ? ' answer' : '') },
      h('span', { class: 'agent-av x', text: 'X0' }),
      h('div', { class: 'agent-bubble x' }, ...parts));
  }

  function afterBubbles(turn) {
    const me = h('div', { class: 'agent-msg me' },
      h('span', { class: 'agent-av me', text: 'YOU' }),
      h('div', { class: 'agent-bubble me', text: turn.q }));
    const reply = turn.a
      ? (turn.bad ? [h('span', { class: 'agent-bad', text: turn.a })] : markdownNodes(turn.a, MD))
      : [h('span', { class: 'tag', text: 'Reading the report.' })];
    return [me, h('div', { class: 'agent-msg answer' },
      h('span', { class: 'agent-av x', text: 'X0' }),
      h('div', { class: 'agent-bubble x' }, h('div', { class: 'agent-who', text: 'MORVAIN-X0' }), ...reply))];
  }

  function currentState() {
    if (jobState === 'ready') return 'ready';
    if (jobState === 'stopped') return 'stopped';
    if (jobState !== 'running') return 'finished';
    if (pending()) return asking ? 'answering' : 'awaiting';
    const last = [...entries].reverse().find((e) => e.from === 'agent' && e.state !== 'answer');
    if (!last) return 'thinking';
    if (last.state === 'awaiting' && last === answered) return 'thinking';
    return STATES[last.state] ? last.state : 'thinking';
  }

  function render(force) {
    // A question is answered once an answer (or a new plan) has arrived.
    if (asking && entries.slice(askBase).some((e) => e.from === 'agent'
      && (e.state === 'answer' || e.state === 'awaiting' || e.state === 'done'))) asking = false;
    if (asking && jobState !== 'running') asking = false;
    const state = currentState();
    const live = pending();
    const key = [entries.length, state, live ? live.round : '', sending, asking, redirectOpen, feedback,
      target, intro ? 1 : 0, runId, after.length, afterBusy].join('|');
    if (key === lastKey && !force) return;
    lastKey = key;
    const powered = POWERED.has(state);
    // A session that has only just begun powers up from off, even when this
    // panel is new (the MORVAIN-X0 tab swaps its idle panel for the session).
    const agentLines = entries.filter((e) => e.from === 'agent').length;
    if (shownState === '' && jobState === 'running' && agentLines <= 1) shownState = 'ready';
    const wasPowered = POWERED.has(shownState);
    character.className = 'glass agent-char state-' + state + (powered ? ' powered' : '')
      + ' mx-mode-' + body.kind + (missing.hidden ? '' : ' no-portrait');
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
    const nearBottom = thread.scrollHeight - thread.scrollTop - thread.clientHeight < 80;
    const total = entries.length + after.length + after.filter((t) => t.a).length;
    const grew = total !== shownCount;
    shownCount = total;
    renderDock(live);
    if (!entries.length && intro) {
      thread.replaceChildren(intro);
      return;
    }
    thread.replaceChildren(...entries.map((e, i) => bubble(e, e === live,
      entries.slice(i + 1).find((x) => x.from === 'operator' && x.decision !== 'ask'))),
    ...after.flatMap(afterBubbles));
    // Follow the conversation, unless the operator scrolled up to read.
    if (grew && (nearBottom || !scrolledOnce)) thread.scrollTop = thread.scrollHeight;
    scrolledOnce = true;
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
        plan: e.plan, source: text(e.source), decision: text(e.decision), brief: e.brief,
        actions: Array.isArray(e.actions) ? e.actions.filter((a) => typeof a === 'string') : [],
      });
    },
    setJob(status) { jobState = status || 'running'; },
    setReport(id) { runId = typeof id === 'string' ? id : ''; },
    setIntro(node) { intro = node; lastKey = ''; },
    setTitle(text) { title.textContent = text; },
    target: () => target,
    character,
    chat,
    render,
  };
}
