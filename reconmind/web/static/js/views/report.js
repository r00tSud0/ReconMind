/*
 * Report (#/report/<run id>), matching docs/design/screens/03_Report.html.
 *
 * Reads GET /api/reports/<run id>: the index entry, report.md, scan.json and
 * what the server derives from them (the findings, the port spectrum and the
 * AI summary). evidence.json is never read here: Raw evidence and Export .md
 * are plain download links to their own routes. Export PDF and Write my own
 * report are not built yet, so they stay visible and disabled.
 *
 * Problem states (09_States.html) show inside the page: a refused target, a
 * stopped scan, an AI summary that could not be written, NVD not answering,
 * unconfirmed ports and an ATT&CK mapping made with the rules only.
 *
 * The page never shows a file path on this machine. Every value from the
 * server is set with textContent, attributes or the CSSOM, never as markup.
 */

import * as api from '../api.js';
import {
  basename, clone, countUp, entryTitle, formatDay, formatDayTime, formatDuration, h, heat,
  isRunId, joinList, markdownNodes, notBuiltButton, parseTime, plural, SEVERITIES, SEVERITY_WORDS, severityKey,
  spectrum,
} from '../ui.js';
import { ACTION_COPY } from './newscan.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const CODE_SEVERITIES = ['high', 'medium', 'low'];
const ACTION_ORDER = Object.keys(ACTION_COPY);
const ACTION_NAMES = {
  surface: 'Surface Map', exploits: 'Exploit Hunt', cves: 'CVE Intel', web: 'Web Fingerprint',
  paths: 'Hidden Paths', vulns: 'Vuln Probe', crypto: 'Crypto Check', smb: 'SMB Recon',
};

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const asList = (v) => (Array.isArray(v) ? v : []);
const asObject = (v) => (isObject(v) ? v : {});
const words = (v) => (typeof v === 'string' ? v : (typeof v === 'number' ? String(v) : ''));

function svg(paths, attrs) {
  const el = document.createElementNS(SVG_NS, 'svg');
  for (const [k, v] of Object.entries(Object.assign({
    width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
    'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true',
  }, attrs))) el.setAttribute(k, String(v));
  for (const d of paths) {
    if (d.startsWith('circle:')) {
      const c = document.createElementNS(SVG_NS, 'circle');
      const [cx, cy, r] = d.slice(7).split(',');
      c.setAttribute('cx', cx);
      c.setAttribute('cy', cy);
      c.setAttribute('r', r);
      el.append(c);
    } else {
      const p = document.createElementNS(SVG_NS, 'path');
      p.setAttribute('d', d);
      el.append(p);
    }
  }
  return el;
}

const ICONS = {
  red: () => svg(['circle:12,12,9', 'M6 6l12 12'], { class: 'alert-icon' }),
  amber: () => svg(['M12 3l9.5 17h-19z', 'M12 10v4M12 17v.01'], { class: 'alert-icon' }),
  grey: () => svg(['circle:12,12,9', 'M12 11v6M12 7.5v.01'], { class: 'alert-icon' }),
};

/* A problem state (09_States.html): tone red, amber or grey. */
function alertBox(tone, title, body, extra) {
  return h('div', { class: 'alert ' + tone, role: tone === 'red' ? 'alert' : 'status' },
    ICONS[tone](),
    h('div', {},
      title ? h('b', { text: title }) : null,
      body ? h('p', { text: body }) : null,
      extra ? h('div', { class: 'notice-extra' }, extra) : null));
}

export function mountReport(view, runId) {
  const { root, refs } = clone('tpl-report');
  view.append(root);
  let alive = true;

  // ---- loading ---------------------------------------------------------

  function showMissing(message) {
    refs.title.textContent = 'Report not found';
    document.title = 'Report not found | ReconMind';
    refs.crumbScan.textContent = 'Not found';
    refs.problem.replaceChildren(alertBox('grey', null, message,
      h('a', { class: 'btn quiet', href: '#/new', text: 'Go to New scan' })));
  }

  function showFailure(res) {
    refs.title.textContent = 'The report could not be loaded';
    let body;
    if (res.status === 0) body = 'The ReconMind server is not answering. Check that python3 -m reconmind.web is still running.';
    else if (res.ok) body = 'The server sent an answer the page could not read.';
    else body = 'The server answered with status ' + res.status + '.';
    const retry = h('button', { type: 'button', class: 'btn quiet', text: 'Try again', onclick: load });
    refs.problem.replaceChildren(alertBox('grey', null, body, retry));
  }

  async function load() {
    refs.problem.replaceChildren();
    if (!isRunId(runId)) {
      showMissing('There is no report with that id.');
      return;
    }
    let res;
    try {
      res = await api.get('/api/reports/' + encodeURIComponent(runId));
    } catch (err) {
      res = { ok: false, status: 0, data: null };
    }
    if (!alive) return;
    if (res.status === 404) {
      showMissing('There is no report with that id.');
      return;
    }
    if (!res.ok || !isObject(res.data) || typeof res.data.markdown !== 'string') {
      showFailure(res);
      return;
    }
    try {
      render(res.data);
    } catch (err) {
      showFailure({ ok: true, status: 200 });
    }
  }

  // ---- header ----------------------------------------------------------

  function renderHead(d, entry, results, isCode) {
    const target = isCode
      ? basename(words(entry.input) || words(results.input)) || 'Source code'
      : words(entry.target) || words(results.target) || 'Unknown target';
    const title = entryTitle(isCode ? { kind: 'code' } : Object.assign({}, entry, {
      preset: entry.preset || asObject(asObject(d.scan).plan).preset,
      customized: entry.customized === true || asObject(asObject(d.scan).plan).customized === true,
    }));
    refs.title.textContent = target;
    document.title = title + ', ' + target + ' | ReconMind';
    refs.crumbTarget.textContent = target;
    refs.crumbTarget.setAttribute('href', '#/targets/' + encodeURIComponent(target));
    // "Standard scan, 12 Nov": the day without the year.
    const day = formatDay(entry.started).split(' ').slice(0, 2).join(' ');
    refs.crumbScan.textContent = title + (day ? ', ' + day : '');

    const when = formatDayTime(entry.started);
    const started = parseTime(entry.started);
    const finished = parseTime(entry.finished);
    let sub = title + (when ? ' on ' + when : '') + '.';
    if (started && finished && finished >= started) sub += ' Took ' + formatDuration((finished - started) / 1000) + '.';
    if (!isCode && entry.mode === 'ai') sub += ' AI analysis on.';
    else if (!isCode && entry.mode === 'standard') sub += ' AI analysis off.';
    else if (isCode) sub += entry.ai_explanation ? ' AI analysis on.' : ' AI analysis off.';
    refs.sub.textContent = sub;

    const base = '/api/reports/' + encodeURIComponent(runId);
    const actions = [];
    if (d.has_evidence === true) {
      actions.push(h('a', { class: 'btn quiet', href: base + '/evidence', download: runId + '_evidence.json', text: 'Raw evidence' }));
    } else {
      actions.push(h('button', {
        type: 'button', class: 'btn quiet', disabled: true,
        title: isCode ? 'Code scans keep no raw evidence' : 'No raw evidence was saved for this run',
      }, 'Raw evidence'));
    }
    actions.push(h('a', { class: 'btn quiet', href: base + '/report.md', download: runId + '.md', text: 'Export .md' }));
    actions.push(notBuiltButton('Export PDF'));
    actions.push(notBuiltButton('Write my own report', 'primary'));
    refs.actions.replaceChildren(...actions);
    return target;
  }

  // ---- counts and spectrum ---------------------------------------------

  function renderCounts(d, results, isCode, refused) {
    if (refused) return;
    const findings = asList(d.findings);
    const severities = isCode ? CODE_SEVERITIES : SEVERITIES;
    const cells = severities.map((s, i) => {
      const n = findings.filter((f) => isObject(f) && f.severity === s).length;
      const num = h('span', { class: 'bignum' });
      countUp(num, n);
      if (i === 0 && n) num.classList.add('hot');
      return h('div', { class: 'count-cell' + (n ? '' : ' zero') }, heat(s), num, h('span', { class: 'help', text: s }));
    });
    let extra;
    if (isCode) {
      const files = asObject(results.files);
      extra = { n: Number(files.count) || 0, label: 'files read' };
    } else {
      extra = { n: asList(results.ports).length, label: 'open ports' };
    }
    const num = h('span', { class: 'bignum' });
    countUp(num, extra.n);
    cells.push(h('div', { class: 'count-cell total' }, h('span', { class: 'heat-gap', 'aria-hidden': 'true' }), num,
      h('span', { class: 'help', text: extra.label })));
    refs.counts.replaceChildren(...cells);
    refs.counts.hidden = false;
  }

  function renderSpectrum(d, isCode, refused) {
    if (isCode || refused) return;
    const ports = asList(d.spectrum).filter(isObject);
    refs.spec.replaceChildren(ports.length ? spectrum(ports, { labels: true })
      : h('p', { class: 'help', text: 'No open ports were found, so there is nothing to draw.' }));
    refs.specWrap.hidden = false;
  }

  // ---- problem states --------------------------------------------------

  function renderNotices(d, results, plan, target, refused, isCode) {
    const boxes = [];
    for (const w of asList(d.warnings)) {
      if (typeof w === 'string') boxes.push(alertBox('grey', null, w));
    }
    if (refused) {
      boxes.push(alertBox('red', target + ' is not on the allowlist',
        'The scan was refused by the authorization gate and nothing was sent to that address.',
        h('a', { class: 'btn quiet', href: '#/new', text: 'Change target' })));
      return boxes;
    }
    if (results.status === 'stopped') {
      const stop = asObject(results.stop);
      const done = asList(stop.finished).map(String);
      const notRun = asList(stop.not_run).map(String);
      boxes.push(alertBox('grey', 'This scan was stopped before it finished',
        'This is a partial report. Finished: ' + (done.length ? done.join(', ') : 'none')
        + '. Did not run: ' + (notRun.length ? notRun.join(', ') : 'none') + '.'));
    }
    if (isCode) return boxes;

    const summary = asObject(d.summary);
    if (summary.state === 'failed' || summary.state === 'rate_limited') {
      const why = summary.state === 'rate_limited'
        ? 'The model was busy and turned the request away (rate limited).'
        : 'The model output did not pass the checks against the tool results.';
      boxes.push(alertBox('amber', 'The AI summary could not be written',
        why + ' Every finding below comes straight from the tools and is complete. Only the written summary is missing.',
        notBuiltButton('Write the summary again')));
    }

    const actions = asList(plan.actions);
    const nvd = results.nvd;
    if (isObject(nvd) && nvd.status && nvd.status !== 'ok' && nvd.status !== 'no-cpe'
        && (!actions.length || actions.includes('cves'))) {
      const products = asList(nvd.products).length;
      boxes.push(alertBox('amber',
        'CVEs were not checked' + (products ? ' for ' + plural(products, 'service', 'services') : ''),
        'NVD did not answer (' + words(nvd.status) + '). This does not mean those services have no CVEs. Exploit Hunt results are not affected.',
        notBuiltButton('Check CVEs again')));
    }

    const unconfirmed = asList(results.unconfirmed_ports)
      .map((u) => (isObject(u) ? u.port : u)).filter((p) => Number.isInteger(p));
    if (unconfirmed.length) {
      boxes.push(alertBox('grey',
        plural(unconfirmed.length, 'port', 'ports') + ' could not be confirmed',
        (unconfirmed.length === 1 ? 'Port ' : 'Ports ') + joinList(unconfirmed)
        + ' answered in the fast pass but not in the detail pass, usually because packets were dropped. They are not counted as findings.',
        notBuiltButton('Rescan these ports')));
    }

    const mapping = results.attack_map;
    if (isObject(mapping) && mapping.status && mapping.status !== 'ok') {
      boxes.push(alertBox('grey', 'Mapped with rules only',
        'The fine-tuned ATT&CK model was not available for this scan, so the techniques come from the built-in rules.',
        h('a', { class: 'btn quiet', href: '#/system', text: 'Open system check' })));
    }
    return boxes;
  }

  // ---- what it means ---------------------------------------------------

  function renderMeaning(d, isCode, refused) {
    if (isCode || refused) return;
    const summary = asObject(d.summary);
    if (summary.state === 'ok' && typeof summary.text === 'string') {
      // The summary's Markdown, built as DOM nodes; HTML in it is never interpreted.
      const body = markdownNodes(summary.text,
        { paragraph: 'meaning-text', heading: 'meaning-subhead', list: 'meaning-list' });
      if (body.length && body[0].tagName === 'P') body[0].className = 'meaning-lead';
      const refsList = asList(summary.unverified).filter((r) => typeof r === 'string');
      if (refsList.length) {
        body.push(h('p', { class: 'help', text: 'Not found in any tool result for this scan: ' + refsList.join(', ') + '.' }));
      }
      refs.meaningBody.replaceChildren(...body);
      refs.meaning.hidden = false;
    } else if (summary.state === 'off') {
      refs.meaningHelp.textContent = 'AI analysis was off for this scan.';
      refs.meaningBody.replaceChildren(h('p', {
        class: 'meaning-text',
        text: 'There is no written summary. The findings below come straight from the tools. Turn AI analysis on in New scan to add a summary, the attack path and what to fix first.',
      }));
      refs.meaning.hidden = false;
    }
  }

  // ---- findings --------------------------------------------------------

  function findingRow(f, index, open) {
    const sev = severityKey(f.severity);
    const ids = asList(f.ids).map(String);
    const evidence = asList(f.evidence).map(String).join('\n');
    const panelId = 'ev-' + index;
    const chev = svg(['M9 6l6 6-6 6'], { width: 16, height: 16, class: 'chev' });
    const btn = h('button', {
      type: 'button', class: 'frow sev-' + sev, 'aria-expanded': 'false', 'aria-controls': panelId,
    },
    chev,
    heat(sev === 'none' ? 'low' : sev),
    h('span', { class: 'frow-main' },
      h('span', { class: 'frow-title', text: words(f.title) || 'Finding' }),
      h('span', { class: 'help', text: (SEVERITY_WORDS[sev] || '') + (f.where ? '. ' + words(f.where) : '') })),
    h('span', { class: 'help frow-source', text: words(f.source) }),
    h('span', { class: 'frow-ids', text: ids.join(', ') }));
    const panel = h('div', { class: 'evw', id: panelId, role: 'region' },
      h('div', {}, h('div', { class: 'ev', text: evidence || 'No tool output was kept for this finding.' })));
    const toggle = (on) => {
      btn.classList.toggle('open', on);
      panel.classList.toggle('open', on);
      btn.setAttribute('aria-expanded', on ? 'true' : 'false');
    };
    btn.addEventListener('click', () => toggle(!btn.classList.contains('open')));
    toggle(open);
    return h('div', { class: 'finding' }, btn, panel);
  }

  function renderFindings(d, isCode, refused) {
    if (refused) return;
    const findings = asList(d.findings).filter(isObject);
    if (findings.length) {
      refs.findings.replaceChildren(...findings.map((f, i) => findingRow(f, i, i === 0)));
    } else {
      refs.findings.replaceChildren(h('p', {
        class: 'help findings-none',
        text: isCode ? 'Semgrep and Bandit found nothing in this code.'
          : 'No findings at low severity or above. CVE matches from NVD are not counted as findings because they match the version only; Export .md lists them.',
      }));
    }
    refs.findingsPanel.hidden = false;
  }

  // ---- ATT&CK and tool coverage ----------------------------------------

  function renderAttack(results) {
    const mapping = results.attack_map;
    if (!isObject(mapping)) {
      refs.attack.replaceChildren(h('p', { class: 'help', text: 'ATT&CK mapping did not run for this scan.' }));
      refs.attackNote.textContent = '';
      return;
    }
    const byId = new Map();
    const lower = new Map();
    for (const p of asList(mapping.ports).filter(isObject)) {
      const port = Number.isInteger(p.port) ? p.port : null;
      for (const t of asList(p.techniques).filter(isObject)) {
        const id = words(t.id);
        if (!id) continue;
        const item = byId.get(id) || { id, name: words(t.name), ports: [], sources: new Set(), confidence: 0 };
        if (port !== null && !item.ports.includes(port)) item.ports.push(port);
        for (const s of asList(t.sources)) item.sources.add(String(s));
        item.confidence = Math.max(item.confidence, Number(t.confidence) || 0);
        byId.set(id, item);
      }
      for (const t of asList(p.lower_confidence).filter(isObject)) {
        const id = words(t.id);
        if (!id || byId.has(id)) continue;
        const item = lower.get(id) || { id, name: words(t.name), ports: [], confidence: 0 };
        if (port !== null && !item.ports.includes(port)) item.ports.push(port);
        item.confidence = Math.max(item.confidence, Number(t.confidence) || 0);
        lower.set(id, item);
      }
    }
    const portText = (ports) => (ports.length ? (ports.length === 1 ? 'Port ' : 'Ports ') + joinList(ports) : 'No port');
    const row = (item, kind) => {
      const conf = Math.max(0, Math.min(1, item.confidence));
      let badge;
      let note;
      let tone = 'ok';
      if (kind === 'lower') {
        badge = 'Lower confidence, ' + conf.toFixed(2);
        note = portText(item.ports) + ', a model suggestion that is not counted as a mapping.';
        tone = 'low';
      } else if (item.sources.has('rule') && [...item.sources].some((s) => s.startsWith('model'))) {
        badge = 'Verified';
        note = portText(item.ports) + '. The rules and the model agree.';
      } else if (item.sources.has('rule')) {
        badge = 'From the rules';
        note = portText(item.ports) + ', from the rules.';
      } else {
        badge = 'Model, ' + conf.toFixed(2);
        note = portText(item.ports) + ', from the model alone.';
        tone = 'model';
      }
      const fill = h('i', { class: 'fill-' + tone });
      fill.style.transform = 'scaleX(' + conf.toFixed(3) + ')';
      return h('div', { class: 'tech' },
        h('div', { class: 'tech-top' },
          h('span', { class: 'tech-id', text: item.id }),
          h('span', { class: 'tech-name', text: item.name || item.id }),
          h('span', { class: 'tech-badge ' + tone, text: badge })),
        h('div', { class: 'bar', 'aria-hidden': 'true' }, fill),
        h('span', { class: 'help', text: note }));
    };
    const rows = [...byId.values()].map((item) => row(item, 'confirmed'));
    rows.push(...[...lower.values()].map((item) => row(item, 'lower')));
    refs.attack.replaceChildren(...(rows.length ? rows
      : [h('p', { class: 'help', text: 'No technique was confirmed for any open port.' })]));
    refs.attackNote.textContent = mapping.status === 'ok'
      ? 'Mapped by the ' + (words(mapping.run_name) || 'fine-tuned') + ' model plus rules. Every ID is checked against MITRE ATT&CK.'
      : 'Mapped by the built-in rules. Every ID is checked against MITRE ATT&CK.';
  }

  function okCount(byPort, count) {
    const results = Object.values(asObject(byPort)).filter((r) => isObject(r) && r.status === 'ok');
    return { checked: results.length, n: results.reduce((sum, r) => sum + count(r), 0) };
  }

  function coverageFor(id, results, chosen) {
    if (!chosen.includes(id)) return { text: 'Not selected', on: false };
    switch (id) {
      case 'surface':
        if (results.status === 'ok' || asList(results.ports).length) {
          return { text: plural(asList(results.ports).length, 'open port', 'open ports'), on: true };
        }
        return { text: 'Did not complete', on: false };
      case 'exploits': {
        const n = asList(results.ports).filter((p) => isObject(p) && asList(p.exploits).length).length;
        return { text: n ? plural(n, 'service matched', 'services matched') : 'No matches', on: true };
      }
      case 'cves': {
        const nvd = results.nvd;
        if (!isObject(nvd)) return { text: 'Did not run', on: false };
        if (nvd.status === 'no-cpe') return { text: 'Nothing to look up', on: false };
        if (nvd.status !== 'ok') return { text: 'Not checked', on: false };
        return { text: plural(asList(nvd.products).length, 'product checked', 'products checked'), on: true };
      }
      case 'web': {
        const r = okCount(results.web, () => 1);
        return r.checked ? { text: plural(r.checked, 'site', 'sites'), on: true } : { text: 'Skipped, no web port', on: false };
      }
      case 'paths': {
        const r = okCount(results.discovery, (x) => asList(x.results).length);
        return r.checked ? { text: plural(r.n, 'path', 'paths'), on: true } : { text: 'Skipped, no web port', on: false };
      }
      case 'vulns': {
        const r = okCount(results.nuclei, (x) => asList(x.findings).length);
        return r.checked ? { text: plural(r.n, 'match', 'matches'), on: true } : { text: 'Skipped, no web port', on: false };
      }
      case 'crypto': {
        const r = okCount(results.tls, () => 1);
        return r.checked ? { text: plural(r.checked, 'TLS port', 'TLS ports'), on: true } : { text: 'Skipped, no TLS', on: false };
      }
      case 'smb': {
        const smb = results.smb;
        if (!isObject(smb)) return { text: 'Skipped, no SMB port', on: false };
        if (smb.status !== 'ok') return { text: 'Did not complete', on: false };
        return { text: plural(asList(smb.shares).length, 'share', 'shares'), on: true };
      }
      default:
        return { text: '', on: false };
    }
  }

  function coverageRow(name, result) {
    return h('div', { class: 'cov' },
      h('span', { class: 'cov-name' }, h('span', { class: 'cov-dot' + (result.on ? ' on' : '') }), name),
      h('span', { class: 'cov-result' + (result.on ? ' on' : ''), text: result.text }));
  }

  function renderCoverage(results, plan, isCode) {
    if (isCode) {
      const tools = asObject(results.tools);
      refs.coverage.replaceChildren(...['semgrep', 'bandit'].map((t) => {
        const r = asObject(tools[t]);
        const ran = r.status === 'ok';
        return coverageRow(t === 'semgrep' ? 'Semgrep' : 'Bandit',
          { text: ran ? 'Ran' : (r.status ? 'Did not run' : 'Not recorded'), on: ran });
      }));
      refs.coverageNote.textContent = 'The code is read, never run.';
      return;
    }
    const chosen = asList(plan.actions).length ? asList(plan.actions).map(String) : ACTION_ORDER;
    refs.coverage.replaceChildren(...ACTION_ORDER.map((id) => coverageRow(ACTION_NAMES[id] || id,
      coverageFor(id, results, chosen))));
    const unconfirmed = asList(results.unconfirmed_ports).length;
    refs.coverageNote.textContent = unconfirmed
      ? plural(unconfirmed, 'unconfirmed port', 'unconfirmed ports') + ', not counted.'
      : 'No unconfirmed ports.';
  }

  // ---- all of it -------------------------------------------------------

  function render(d) {
    const entry = asObject(d.entry);
    const scan = asObject(d.scan);
    const results = asObject(scan.results);
    const plan = asObject(scan.plan);
    const isCode = d.kind === 'code';
    const refused = (entry.status || results.status) === 'refused';

    const target = renderHead(d, entry, results, isCode);
    renderSpectrum(d, isCode, refused);
    renderCounts(d, results, isCode, refused);
    refs.notices.replaceChildren(...renderNotices(d, results, plan, target, refused, isCode));
    renderMeaning(d, isCode, refused);
    renderFindings(d, isCode, refused);
    if (!refused) {
      if (isCode) refs.attackPanel.hidden = true;
      else renderAttack(results);
      renderCoverage(results, plan, isCode);
      refs.bottom.hidden = false;
    }
  }

  load();
  return () => { alive = false; };
}
