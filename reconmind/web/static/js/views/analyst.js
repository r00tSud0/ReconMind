/*
 * Your report (#/analyst/<id>), matching docs/design/screens/05_AnalystReport.html.
 *
 * The analyst's own report of a target, started from a scan (its facts and
 * findings copied in) or from a blank page, on Targets, Your reports. It is
 * saved to GET/POST /api/analyst/<id>, apart from the tool reports, which
 * never change. Changes save on their own a moment after typing stops, and
 * with Save report. Export .md downloads it; Export PDF prints it (print.js).
 *
 * Every value is set with .value, textContent or attributes, never as markup.
 */

import * as api from '../api.js';
import { printDocument } from '../print.js';
import { clock, formatDayTime, h, plural } from '../ui.js';

const SAVE_DELAY = 1200;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_NAMES = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const FINDING_STATUS = { open: 'Open', fixed: 'Fixed', accepted: 'Risk accepted', false_positive: 'False positive' };
const STATUS = { draft: 'Draft', review: 'In review', final: 'Final' };
const CLASSES = { confidential: 'Confidential', internal: 'Internal', public: 'Public' };
const RISKS = { '': 'Not set', critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' };
const FIX_DAYS = { critical: '7 days', high: '30 days', medium: '90 days', low: '180 days', info: '365 days' };

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (typeof v === 'string' ? v : '');
let uid = 0;

function blankFinding() {
  return {
    title: '', severity: 'medium', status: 'open', affected: '', port: '', cves: '', attack: '', cvss: '',
    description: '', impact: '', evidence: '', reproduce: '', recommendation: '', references: '',
    fix_by: FIX_DAYS.medium, owner: '',
  };
}

export function mountAnalyst(view, reportId) {
  let alive = true;
  let data = null;
  let timer = null;
  let saving = false;
  let dirty = false;
  const page = h('main', { class: 'page page-wide analyst-page' });
  view.append(page);
  const status = h('span', { class: 'help', 'aria-live': 'polite', text: '' });

  // ---- fields bound to the report ----------------------------------------

  function changed() {
    dirty = true;
    status.textContent = 'Unsaved changes';
    if (timer) clearTimeout(timer);
    timer = setTimeout(save, SAVE_DELAY);
  }

  function control(obj, key, opts) {
    const id = 'af-' + (++uid);
    let el;
    if (opts.choices) {
      el = h('select', { id, class: 'field' }, ...Object.entries(opts.choices).map(([v, t]) =>
        h('option', { value: v, text: t })));
      el.value = str(obj[key]);
      el.addEventListener('change', () => { obj[key] = el.value; changed(); if (opts.onChange) opts.onChange(); });
    } else {
      el = h(opts.long ? 'textarea' : 'input', Object.assign({ id, class: 'field' + (opts.mono ? ' field-mono' : ''),
        spellcheck: opts.mono ? 'false' : 'true' }, opts.long ? { rows: String(opts.rows || 4) } : { type: 'text' },
      opts.max ? { maxlength: String(opts.max) } : {}, opts.placeholder ? { placeholder: opts.placeholder } : {}));
      el.value = str(obj[key]);
      el.addEventListener('input', () => { obj[key] = el.value; changed(); if (opts.onChange) opts.onChange(); });
    }
    return h('div', { class: 'af' + (opts.wide ? ' wide' : '') }, h('label', { class: 'label', for: id, text: opts.label }), el);
  }

  function section(num, title, ...body) {
    return h('section', { class: 'glass panel analyst-sec reveal' },
      h('div', { class: 'head' }, h('h2', { class: 'h2' }, h('span', { class: 'sec-num', text: num }), title)),
      h('div', { class: 'body af-grid' }, ...body));
  }

  // ---- findings ------------------------------------------------------------

  const findingsBox = h('div', { class: 'af-findings wide' });
  const planBody = h('tbody');
  const countText = h('span', { class: 'help' });

  function renderPlan() {
    const list = data.findings;
    countText.textContent = plural(list.length, 'finding', 'findings');
    planBody.replaceChildren(...list.map((f, i) => h('tr', {},
      h('td', { class: 'num', text: 'F' + String(i + 1).padStart(2, '0') }),
      h('td', { text: f.title || 'Untitled' }),
      h('td', {}, h('span', { class: 'sev-word sev-' + f.severity, text: SEV_NAMES[f.severity] || f.severity })),
      h('td', { text: f.fix_by }), h('td', { text: f.owner }))));
  }

  function findingCard(f, index) {
    const head = h('span', { class: 'af-fhead-title', text: f.title || 'Untitled finding' });
    const sev = h('span', { class: 'sev-word sev-' + f.severity, text: SEV_NAMES[f.severity] });
    const refresh = () => {
      head.textContent = f.title || 'Untitled finding';
      sev.textContent = SEV_NAMES[f.severity];
      sev.className = 'sev-word sev-' + f.severity;
      renderPlan();
    };
    const remove = h('button', { type: 'button', class: 'btn quiet btn-small', text: 'Remove' });
    remove.addEventListener('click', () => {
      data.findings.splice(data.findings.indexOf(f), 1);
      renderFindings();
      changed();
    });
    const body = h('div', { class: 'af-grid' },
      control(f, 'title', { label: 'Title', max: 300, wide: true, onChange: refresh }),
      control(f, 'severity', { label: 'Severity', choices: SEV_NAMES, onChange: () => {
        if (!f.fix_by || Object.values(FIX_DAYS).includes(f.fix_by)) f.fix_by = FIX_DAYS[f.severity];
        refresh();
      } }),
      control(f, 'status', { label: 'Status', choices: FINDING_STATUS }),
      control(f, 'cvss', { label: 'CVSS score and vector', max: 120, mono: true }),
      control(f, 'affected', { label: 'Affected host', max: 200, mono: true }),
      control(f, 'port', { label: 'Port and service', max: 60, mono: true }),
      control(f, 'cves', { label: 'CVE IDs', max: 400, mono: true }),
      control(f, 'attack', { label: 'ATT&CK technique', max: 200, mono: true }),
      control(f, 'description', { label: 'Description', long: true, max: 6000, wide: true }),
      control(f, 'impact', { label: 'Impact', long: true, rows: 3, max: 3000, wide: true }),
      control(f, 'evidence', { label: 'Evidence', long: true, rows: 5, max: 8000, mono: true, wide: true }),
      control(f, 'reproduce', { label: 'Steps to reproduce', long: true, rows: 3, max: 4000, wide: true }),
      control(f, 'recommendation', { label: 'Recommendation', long: true, rows: 3, max: 4000, wide: true }),
      control(f, 'references', { label: 'References', long: true, rows: 2, max: 2000, wide: true }),
      control(f, 'fix_by', { label: 'Fix by', max: 40, onChange: refresh }),
      control(f, 'owner', { label: 'Owner', max: 120, onChange: refresh }));
    const details = h('details', { class: 'af-finding' },
      h('summary', {}, h('span', { class: 'num af-fid', text: 'F' + String(index + 1).padStart(2, '0') }), head, sev),
      body, h('div', { class: 'later-buttons' }, remove));
    return details;
  }

  function renderFindings() {
    findingsBox.replaceChildren(...data.findings.map(findingCard));
    renderPlan();
  }

  // ---- save, export, delete -----------------------------------------------

  async function save() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (!data || saving) { if (saving) timer = setTimeout(save, SAVE_DELAY); return; }
    saving = true;
    dirty = false;
    status.textContent = 'Saving';
    const res = await api.post('/api/analyst/' + reportId, { fields: data.fields, findings: data.findings });
    saving = false;
    if (!alive) return;
    if (res.ok && isObject(res.data) && isObject(res.data.report)) {
      if (!dirty) status.textContent = (STATUS[data.fields.status] || 'Draft') + ' saved at ' + clock(new Date());
    } else {
      dirty = true;
      status.textContent = isObject(res.data) && typeof res.data.message === 'string' ? res.data.message
        : 'Not saved. The server is not answering.';
    }
  }

  function printIt() {
    const f = data.fields;
    const fid = (i) => 'F' + String(i + 1).padStart(2, '0');
    const counts = SEVERITIES.map((s) => [SEV_NAMES[s], data.findings.filter((x) => x.severity === s).length]);
    printDocument({
      label: (CLASSES[f.classification] || 'Confidential').toUpperCase(),
      title: f.title || 'Assessment of ' + data.folder,
      subtitle: [STATUS[f.status], f.client].filter(Boolean).join('. ') + (data.source ? '. Started from ' + data.source + '.' : ''),
      meta: [['Target', data.folder], ['Assessment type', f.assessment_type], ['Testing', [f.testing_started, f.testing_ended].filter(Boolean).join(' to ')],
        ['Prepared by', f.prepared_by], ['Reviewed by', f.reviewed_by], ['Report date', f.report_date], ['Contact', f.contact]],
      sections: [
        { title: 'Executive summary', blocks: [
          f.overall_risk ? { strong: 'Overall risk: ' + RISKS[f.overall_risk] } : null,
          f.summary ? { p: f.summary } : null,
          f.recommendations ? { kv: [['Top recommendations', f.recommendations]] } : null,
          { table: { head: ['Severity', 'Findings'], rows: counts.concat([['Total', data.findings.length]]), sev: 0 } },
        ].filter(Boolean) },
        { title: 'Scope and method', blocks: [{ kv: [['In scope', f.in_scope], ['Out of scope', f.out_of_scope], ['Tools', f.tools],
          ['Methodology', f.method], ['Limitations', f.limitations], ['Authorization', f.authorization]] }] },
        { title: 'Findings summary', blocks: data.findings.length ? [{ table: { head: ['ID', 'Finding', 'Severity', 'Status', 'Port'],
          rows: data.findings.map((x, i) => [fid(i), x.title, x.severity, FINDING_STATUS[x.status], x.port]), sev: 2 } }] : [{ p: 'No findings.' }] },
        { title: 'Detailed findings', blocks: data.findings.map((x, i) => ({ finding: {
          id: fid(i), title: x.title, severity: x.severity,
          kv: [['CVSS', x.cvss], ['Status', FINDING_STATUS[x.status]], ['Affected', x.affected], ['Port', x.port], ['CVE', x.cves], ['ATT&CK', x.attack]],
          parts: [['What it is', x.description], ['Impact', x.impact], ['Steps to reproduce', x.reproduce], ['Fix', x.recommendation], ['References', x.references]],
          evidence: x.evidence } })) },
        { title: 'Attack path', blocks: f.attack_path ? [{ p: f.attack_path }] : [] },
        { title: 'Remediation plan', blocks: data.findings.length ? [{ table: { head: ['ID', 'Finding', 'Severity', 'Fix by', 'Owner'],
          rows: data.findings.map((x, i) => [fid(i), x.title, x.severity, x.fix_by, x.owner]), sev: 2 } }] : [] },
        { title: 'Conclusion', blocks: f.conclusion ? [{ p: f.conclusion }] : [] },
        { title: 'Sign off', blocks: [{ kv: [['Analyst', f.signed_by], ['Date', f.signed_date]] },
          f.confirmed ? { p: 'The analyst confirms these findings are accurate and were found within the authorized scope.' } : null].filter(Boolean) },
      ],
      footer: 'Written with ReconMind. The tool reports this draws on are unchanged.',
    });
  }

  // ---- page ------------------------------------------------------------------

  function build() {
    const f = data.fields;
    document.title = (f.title || 'Your report') + ' | ReconMind';
    const saveBtn = h('button', { type: 'button', class: 'btn primary', text: 'Save report' });
    saveBtn.addEventListener('click', save);
    const pdf = h('button', { type: 'button', class: 'btn quiet', text: 'Export PDF',
      title: 'Opens the print dialog. Choose Save as PDF, or Print to File in the ReconMind window.' });
    pdf.addEventListener('click', async () => { if (dirty) await save(); printIt(); });
    const md = h('a', { class: 'btn quiet', href: '/api/analyst/' + reportId + '/report.md', download: 'report_' + reportId + '.md', text: 'Export .md' });
    md.addEventListener('click', (e) => { if (dirty) { e.preventDefault(); save().then(() => md.click()); } });
    const del = h('button', { type: 'button', class: 'btn quiet', text: 'Delete' });
    del.addEventListener('click', async () => {
      if (del.dataset.sure !== '1') { del.dataset.sure = '1'; del.textContent = 'Delete for good?'; return; }
      if (timer) clearTimeout(timer);
      const res = await api.post('/api/analyst/' + reportId, { delete: true });
      if (alive && res.ok) location.hash = '#/targets/' + encodeURIComponent(data.folder);
    });
    const addFinding = h('button', { type: 'button', class: 'btn quiet', text: 'Add a finding' });
    addFinding.addEventListener('click', () => {
      const fresh = Object.assign(blankFinding(), { affected: data.folder });
      data.findings.push(fresh);
      renderFindings();
      const cards = findingsBox.querySelectorAll('details');
      const last = cards[cards.length - 1];
      if (last) { last.open = true; last.scrollIntoView({ block: 'center' }); }
      changed();
    });
    renderFindings();
    const confirmBox = h('input', { type: 'checkbox', id: 'af-confirm' });
    confirmBox.checked = f.confirmed === true;
    confirmBox.addEventListener('change', () => { f.confirmed = confirmBox.checked; changed(); });
    const source = data.source ? h('p', { class: 'help', text: 'Started from ' + data.source
      + '. That report is never changed. Yours is saved next to it, so the original evidence stays as the tools wrote it.' }) : null;

    page.replaceChildren(
      h('nav', { class: 'crumbs reveal', 'aria-label': 'Breadcrumb' },
        h('a', { href: '#/targets', text: 'Targets' }), h('span', { 'aria-hidden': 'true', text: '/' }),
        h('a', { href: '#/targets/' + encodeURIComponent(data.folder), text: data.folder }),
        h('span', { 'aria-hidden': 'true', text: '/' }), h('span', { text: 'Your report' })),
      h('div', { class: 'analyst-top reveal' },
        h('h1', { class: 'title page-title', text: 'Your report' }),
        h('p', { class: 'lead', text: 'Created ' + (formatDayTime(data.created) || '') + '. Changes save on their own.' }), source),
      section('01', 'Report details',
        control(f, 'title', { label: 'Report title', max: 200, wide: true }),
        control(f, 'status', { label: 'Status', choices: STATUS }),
        control(f, 'classification', { label: 'Classification', choices: CLASSES }),
        control(f, 'client', { label: 'Client or organization', max: 200 }),
        control(f, 'report_date', { label: 'Report date', max: 40 }),
        control(f, 'prepared_by', { label: 'Prepared by', max: 120 }),
        control(f, 'reviewed_by', { label: 'Reviewed by', max: 120 }),
        control(f, 'contact', { label: 'Contact', max: 200 })),
      section('02', 'Scope and method',
        control(f, 'assessment_type', { label: 'Assessment type', max: 80 }),
        control(f, 'testing_started', { label: 'Testing started', max: 40 }),
        control(f, 'testing_ended', { label: 'Testing ended', max: 40 }),
        control(f, 'in_scope', { label: 'In scope', long: true, rows: 2, max: 2000, wide: true }),
        control(f, 'out_of_scope', { label: 'Out of scope', long: true, rows: 2, max: 2000, wide: true }),
        control(f, 'tools', { label: 'Tools used', long: true, rows: 2, max: 1000, wide: true }),
        control(f, 'method', { label: 'Methodology', long: true, max: 6000, wide: true }),
        control(f, 'limitations', { label: 'Limitations', long: true, rows: 3, max: 3000, wide: true }),
        control(f, 'authorization', { label: 'Authorization reference', long: true, rows: 2, max: 1000, wide: true })),
      section('03', 'Executive summary',
        control(f, 'overall_risk', { label: 'Overall risk', choices: RISKS }),
        control(f, 'summary', { label: 'Summary', long: true, rows: 6, max: 8000, wide: true }),
        control(f, 'recommendations', { label: 'Top recommendations', long: true, rows: 4, max: 6000, wide: true })),
      section('04', 'Findings', h('div', { class: 'wide af-findings-head' }, countText, addFinding), findingsBox),
      section('05', 'Attack path',
        control(f, 'attack_path', { label: 'How the findings chain together', long: true, rows: 5, max: 6000, wide: true })),
      section('06', 'Remediation plan',
        h('p', { class: 'help wide', text: 'Built from your findings. Set Fix by and Owner on each finding.' }),
        h('div', { class: 'wide table-wrap' }, h('table', { class: 'af-table' },
          h('thead', {}, h('tr', {}, ...['ID', 'Finding', 'Severity', 'Fix by', 'Owner'].map((t) => h('th', { text: t })))),
          planBody))),
      section('07', 'Conclusion',
        control(f, 'conclusion', { label: 'Overall assessment and next steps', long: true, rows: 5, max: 6000, wide: true })),
      section('08', 'Sign off',
        control(f, 'signed_by', { label: 'Analyst', max: 120 }),
        control(f, 'signed_date', { label: 'Date', max: 40 }),
        h('label', { class: 'af-check wide', for: 'af-confirm' }, confirmBox,
          'I confirm these findings are accurate and were found within the authorized scope')),
      h('div', { class: 'glass analyst-bar' }, status,
        h('div', { class: 'later-buttons' }, del, md, pdf, saveBtn)));
    status.textContent = (STATUS[f.status] || 'Draft') + ', last saved ' + (formatDayTime(data.updated) || '');
  }

  async function load() {
    if (!/^[0-9a-f]{16}$/.test(reportId)) {
      page.replaceChildren(h('section', { class: 'glass later' }, h('h1', { class: 'h2', text: 'There is no report of yours with that id' }),
        h('a', { class: 'btn quiet', href: '#/targets', text: 'Open Targets' })));
      return;
    }
    const res = await api.get('/api/analyst/' + reportId);
    if (!alive) return;
    if (!res.ok || !isObject(res.data) || !isObject(res.data.fields)) {
      page.replaceChildren(h('section', { class: 'glass later' },
        h('h1', { class: 'h2', text: res.status === 404 ? 'There is no report of yours with that id' : 'Your report could not be loaded' }),
        h('a', { class: 'btn quiet', href: '#/targets', text: 'Open Targets' })));
      return;
    }
    data = res.data;
    data.findings = Array.isArray(data.findings) ? data.findings.filter(isObject).map((x) => Object.assign(blankFinding(), x)) : [];
    build();
  }

  const beforeUnload = (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } };
  window.addEventListener('beforeunload', beforeUnload);
  load();
  return () => {
    alive = false;
    window.removeEventListener('beforeunload', beforeUnload);
    // Leaving the page saves what is left, so nothing typed is lost.
    if (dirty && data) {
      if (timer) clearTimeout(timer);
      api.post('/api/analyst/' + reportId, { fields: data.fields, findings: data.findings });
    }
  };
}
