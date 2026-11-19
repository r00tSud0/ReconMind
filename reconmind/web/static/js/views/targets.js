/*
 * Targets (#/targets and #/targets/<target>), matching
 * docs/design/screens/04_Targets.html.
 *
 * The folders come from the report history (GET /api/history): one folder
 * per network target, and one per code input, named by its file or folder
 * name only (never its path). Each folder lists its scans, newest first;
 * opening a scan opens its report (#/report/<run id>). The small port
 * spectrum on each scan row is read from that scan's report, a few at a
 * time, for the open folder only.
 *
 * Notes keeps what the analyst notices about the target (GET /api/workspace,
 * POST /api/workspace/notes). Your reports lists the reports the analyst
 * writes (#/analyst/<id>), started from the latest scan or from a blank page.
 * Both are saved apart from the tool reports, which never change.
 *
 * Every value from the server is set with textContent, attributes or the
 * CSSOM, never as markup.
 */

import * as api from '../api.js';
import {
  basename, clone, entryTitle, formatDay, formatDayTime, h, isRunId,
  plural, reducedMotion, SEVERITIES, spectrum,
} from '../ui.js';

const CODE_SEVERITIES = ['high', 'medium', 'low'];
const MAX_SPECTRA = 12;
const TABS = ['scans', 'notes', 'reports'];
const SVG_NS = 'http://www.w3.org/2000/svg';

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/* The folder name of an index entry: the target, or the code input's own name. */
function folderName(entry) {
  if (entry.kind === 'code') return basename(typeof entry.input === 'string' ? entry.input : '') || 'Source code';
  return typeof entry.target === 'string' && entry.target ? entry.target : 'Unknown target';
}

/* {severity, count} of the worst finding in an entry, or null when it has none. */
function worst(entry) {
  const findings = isObject(entry.findings) ? entry.findings : {};
  const levels = entry.kind === 'code' ? CODE_SEVERITIES : SEVERITIES;
  for (const s of levels) {
    const n = Number(findings[s]) || 0;
    if (n > 0) return { severity: s, count: n };
  }
  return null;
}

function tagFor(entry) {
  if (entry.status === 'refused') return { text: 'Refused', cls: 'muted' };
  const w = worst(entry);
  if (entry.stopped === true || entry.status === 'stopped') {
    return w ? { text: 'Stopped, ' + w.count + ' ' + w.severity, cls: 'sev-' + w.severity } : { text: 'Stopped', cls: 'muted' };
  }
  return w ? { text: w.count + ' ' + w.severity, cls: 'sev-' + w.severity } : { text: 'No findings', cls: 'muted' };
}

function metaFor(entry) {
  const when = formatDayTime(entry.started);
  const head = when ? when + '. ' : '';
  if (entry.status === 'refused') return head + 'Refused by the authorization gate. Nothing was sent.';
  if (entry.kind === 'code') {
    const languages = isObject(entry.languages) ? entry.languages : {};
    const files = Object.values(languages).reduce((a, b) => a + (Number(b) || 0), 0);
    const findings = isObject(entry.findings) ? Object.values(entry.findings).reduce((a, b) => a + (Number(b) || 0), 0) : 0;
    return head + plural(findings, 'finding', 'findings') + ' in ' + plural(files, 'file', 'files') + '.';
  }
  const ports = Number(entry.open_ports) || 0;
  const checks = Array.isArray(entry.actions) ? entry.actions.length : 0;
  let text = head + plural(ports, 'open port', 'open ports');
  if (entry.ports_spec === 'all') text += ' on all 65535';
  if (checks) text += ', ' + plural(checks, 'check', 'checks') + (entry.agent === true ? ' run by MORVAIN-X0' : '');
  text += '.';
  if (entry.stopped === true || entry.status === 'stopped') text += ' Stopped before it finished.';
  return text;
}

function fileIcon() {
  const el = document.createElementNS(SVG_NS, 'svg');
  for (const [k, v] of Object.entries({
    width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
    'stroke-width': 1.8, 'stroke-linejoin': 'round', 'aria-hidden': 'true', class: 'file-icon',
  })) el.setAttribute(k, String(v));
  for (const d of ['M6 3h8l4 4v14H6z', 'M14 3v4h4M9 12h6M9 16h6']) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d);
    el.append(p);
  }
  return el;
}

export function mountTargets(view, wanted) {
  let alive = true;
  let folders = [];
  let selected = null;
  let tab = 'scans';
  let refs = null;
  const spectra = new Map(); // run id to [{port, service, severity}] or null

  // ---- empty and failure states ----------------------------------------

  function showEmpty(message) {
    const { root, refs: r } = clone('tpl-targets-empty');
    if (message) r.text.textContent = message;
    view.replaceChildren(root);
  }

  // ---- folders ---------------------------------------------------------

  function group(entries) {
    const byKey = new Map();
    for (const entry of entries) {
      const kind = entry.kind === 'code' ? 'code' : 'recon';
      const name = folderName(entry);
      const key = kind + '|' + name;
      if (!byKey.has(key)) byKey.set(key, { key, kind, name, scans: [] });
      byKey.get(key).scans.push(entry);
    }
    // Newest activity first; the history is already newest first.
    return Array.from(byKey.values());
  }

  function folderButton(folder) {
    const latest = folder.scans.find((e) => e.status !== 'refused') || folder.scans[0];
    const tag = tagFor(latest);
    const sub = folder.kind === 'code' ? 'Source code, ' + plural(folder.scans.length, 'scan', 'scans')
      : plural(folder.scans.length, 'scan', 'scans');
    const btn = h('button', {
      type: 'button', class: 'folder', 'aria-pressed': 'false',
      onclick: () => select(folder, true),
    },
    h('span', { class: 'folder-text' },
      h('span', { class: 'folder-name num', text: folder.name }),
      h('span', { class: 'help small', text: sub })),
    h('span', { class: 'folder-tag ' + tag.cls, text: tag.text }));
    folder.button = btn;
    return btn;
  }

  function applyFilter() {
    const q = refs.filter.value.trim().toLowerCase();
    let shown = 0;
    for (const folder of folders) {
      const match = !q || folder.name.toLowerCase().includes(q);
      folder.button.hidden = !match;
      if (match) shown += 1;
    }
    refs.noMatch.hidden = shown > 0;
  }

  // ---- the open folder -------------------------------------------------

  function placeTabIndicator() {
    const btn = refs.tabs.querySelector('[data-tab="' + tab + '"]');
    if (!btn) return;
    refs.tabInd.style.width = btn.offsetWidth + 'px';
    refs.tabInd.style.transform = 'translateX(' + btn.offsetLeft + 'px)';
  }

  function scanRow(entry, index) {
    const tag = tagFor(entry);
    const runId = isRunId(entry.run_id) ? entry.run_id : null;
    const visual = entry.kind === 'code' ? fileIcon()
      : h('span', { class: 'mini-slot', 'data-run': runId || '' }, h('span', { class: 'mini mini-empty', 'aria-hidden': 'true' }));
    const body = [
      visual,
      h('span', { class: 'scan-text' },
        h('span', { class: 'scan-name', text: entryTitle(entry) }),
        h('span', { class: 'help', text: metaFor(entry) })),
      h('span', { class: 'scan-tag ' + tag.cls, text: tag.text }),
    ];
    const row = runId
      ? h('a', { class: 'scan', href: '#/report/' + encodeURIComponent(runId) }, ...body)
      : h('div', { class: 'scan', title: 'This scan has no saved report' }, ...body);
    if (!reducedMotion()) row.style.animationDelay = (0.15 + index * 0.07).toFixed(2) + 's';
    return row;
  }

  function fillSpectrum(slot, ports) {
    if (!slot.isConnected) return;
    slot.replaceChildren(Array.isArray(ports) ? spectrum(ports, { mini: true })
      : h('span', { class: 'mini mini-empty', 'aria-hidden': 'true' }));
  }

  /* Read the port spectrum of the folder's scans, one report at a time. */
  async function loadSpectra(panel) {
    const slots = Array.from(panel.querySelectorAll('.mini-slot')).filter((s) => s.dataset.run).slice(0, MAX_SPECTRA);
    for (const slot of slots) {
      const runId = slot.dataset.run;
      if (!spectra.has(runId)) {
        let res;
        try {
          res = await api.get('/api/reports/' + encodeURIComponent(runId), { quiet: true });
        } catch (err) {
          res = { ok: false, data: null };
        }
        if (!alive) return;
        spectra.set(runId, res.ok && isObject(res.data) && Array.isArray(res.data.spectrum)
          ? res.data.spectrum.filter(isObject) : null);
      }
      fillSpectrum(slot, spectra.get(runId));
    }
  }

  // ---- notes and your reports -------------------------------------------

  async function workspaceOf(folder) {
    const res = await api.get('/api/workspace?folder=' + encodeURIComponent(folder.name));
    return res.ok && isObject(res.data) ? res.data : null;
  }

  function problem(slot, res, fallback) {
    const msg = res && isObject(res.data) && typeof res.data.message === 'string' ? res.data.message : fallback;
    slot.textContent = msg;
    slot.hidden = false;
  }

  function noteCard(folder, note, refresh) {
    const body = h('p', { class: 'note-text', text: String(note.text || '') });
    const when = h('span', { class: 'help small', text: formatDayTime(note.updated || note.created) || '' });
    const edit = h('button', { type: 'button', class: 'btn quiet btn-small', text: 'Edit' });
    const del = h('button', { type: 'button', class: 'btn quiet btn-small', text: 'Delete' });
    const err = h('p', { class: 'field-error', hidden: true });
    const card = h('div', { class: 'note-card' }, body, h('div', { class: 'note-foot' }, when,
      h('span', { class: 'note-buttons' }, edit, del)), err);
    edit.addEventListener('click', () => {
      const area = h('textarea', { class: 'field note-field', rows: '4', maxlength: '5000' });
      area.value = String(note.text || '');
      const save = h('button', { type: 'button', class: 'btn primary btn-small', text: 'Save' });
      const cancel = h('button', { type: 'button', class: 'btn quiet btn-small', text: 'Cancel' });
      card.replaceChildren(area, h('div', { class: 'note-buttons' }, save, cancel), err);
      area.focus();
      cancel.addEventListener('click', refresh);
      save.addEventListener('click', async () => {
        save.disabled = true;
        const res = await api.post('/api/workspace/notes/' + note.id, { folder: folder.name, text: area.value });
        if (!alive) return;
        if (res.ok) refresh();
        else { save.disabled = false; problem(err, res, 'The note could not be saved.'); }
      });
    });
    del.addEventListener('click', async () => {
      del.disabled = true;
      const res = await api.post('/api/workspace/notes/' + note.id, { folder: folder.name, delete: true });
      if (!alive) return;
      if (res.ok) refresh();
      else { del.disabled = false; problem(err, res, 'The note could not be deleted.'); }
    });
    return card;
  }

  async function notesPanel(folder) {
    const area = h('textarea', { class: 'field note-field', rows: '3', maxlength: '5000',
      placeholder: 'What you noticed about ' + folder.name + '. Plain text, saved next to its scans.' });
    const add = h('button', { type: 'button', class: 'btn primary', text: 'Add note' });
    const err = h('p', { class: 'field-error', hidden: true });
    const list = h('div', { class: 'note-list' }, h('p', { class: 'help', text: 'Loading notes.' }));
    const panel = h('div', { class: 'panel-notes' },
      h('label', { class: 'sr-only', text: 'New note' }), area,
      h('div', { class: 'later-buttons' }, add), err, list);
    const refresh = async () => {
      const data = await workspaceOf(folder);
      if (!alive || selected !== folder || tab !== 'notes') return;
      const notes = data && Array.isArray(data.notes) ? data.notes.filter(isObject) : null;
      if (!notes) list.replaceChildren(h('p', { class: 'help', text: 'The notes could not be loaded.' }));
      else if (!notes.length) list.replaceChildren(h('p', { class: 'help', text: 'No notes yet.' }));
      else list.replaceChildren(...notes.map((n) => noteCard(folder, n, refresh)));
    };
    add.addEventListener('click', async () => {
      err.hidden = true;
      if (!area.value.trim()) { problem(err, null, 'Write something in the note first.'); return; }
      add.disabled = true;
      const res = await api.post('/api/workspace/notes', { folder: folder.name, text: area.value });
      if (!alive) return;
      add.disabled = false;
      if (res.ok) { area.value = ''; refresh(); } else problem(err, res, 'The note could not be saved.');
    });
    refresh();
    return panel;
  }

  const STATUS_NAMES = { draft: 'Draft', review: 'In review', final: 'Final' };

  async function reportsPanel(folder) {
    const latest = folder.scans.find((e) => isRunId(e.run_id) && e.status !== 'refused');
    const fromScan = h('button', { type: 'button', class: 'btn primary', text: 'Start from the latest scan' });
    const blank = h('button', { type: 'button', class: 'btn quiet', text: 'Start blank' });
    fromScan.disabled = !latest;
    if (!latest) fromScan.title = 'This target has no finished scan yet';
    const err = h('p', { class: 'field-error', hidden: true });
    const list = h('div', { class: 'scan-list' }, h('p', { class: 'help', text: 'Loading your reports.' }));
    async function create(fromRun) {
      fromScan.disabled = true;
      blank.disabled = true;
      const res = await api.post('/api/analyst', fromRun ? { folder: folder.name, from_run: fromRun } : { folder: folder.name });
      if (!alive) return;
      if (res.ok && isObject(res.data) && isObject(res.data.report)) {
        location.hash = '#/analyst/' + res.data.report.id;
        return;
      }
      fromScan.disabled = !latest;
      blank.disabled = false;
      problem(err, res, 'The report could not be started.');
    }
    fromScan.addEventListener('click', () => create(latest.run_id));
    blank.addEventListener('click', () => create(null));
    const panel = h('div', { class: 'panel-later' },
      h('p', { class: 'help', text: 'Write your own assessment of this target. It is saved next to the scans, '
        + 'and the tool reports stay exactly as the tools wrote them.' }),
      h('div', { class: 'later-buttons' }, fromScan, blank), err, list);
    const data = await workspaceOf(folder);
    if (!alive || selected !== folder || tab !== 'reports') return panel;
    const reports = data && Array.isArray(data.reports) ? data.reports.filter(isObject) : null;
    if (!reports) list.replaceChildren(h('p', { class: 'help', text: 'Your reports could not be loaded.' }));
    else if (!reports.length) list.replaceChildren(h('p', { class: 'help', text: 'No reports of yours yet.' }));
    else {
      list.replaceChildren(...reports.map((r) => h('a', { class: 'scan', href: '#/analyst/' + r.id },
        fileIcon(),
        h('span', { class: 'scan-text' },
          h('span', { class: 'scan-name', text: String(r.title || 'Untitled report') }),
          h('span', { class: 'help', text: 'Last saved ' + (formatDayTime(r.updated) || 'just now') + '. '
            + plural(Number(r.findings) || 0, 'finding', 'findings') + '.' })),
        h('span', { class: 'scan-tag muted', text: STATUS_NAMES[r.status] || 'Draft' }))));
    }
    return panel;
  }

  function renderPanel() {
    for (const btn of refs.tabs.querySelectorAll('[data-tab]')) {
      const on = btn.dataset.tab === tab;
      btn.classList.toggle('on', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
    }
    placeTabIndicator();
    const folder = selected;
    let panel;
    if (tab === 'scans') {
      panel = h('div', { class: 'scan-list' }, ...folder.scans.map(scanRow));
      refs.panel.replaceChildren(panel);
      loadSpectra(panel);
      return;
    }
    const want = tab;
    refs.panel.replaceChildren(h('p', { class: 'help', text: 'Loading.' }));
    (tab === 'notes' ? notesPanel(folder) : reportsPanel(folder)).then((node) => {
      if (alive && selected === folder && tab === want) refs.panel.replaceChildren(node);
    });
  }

  function select(folder, fromClick) {
    selected = folder;
    for (const f of folders) {
      const on = f === folder;
      f.button.classList.toggle('on', on);
      f.button.setAttribute('aria-pressed', on ? 'true' : 'false');
    }
    refs.title.textContent = folder.name;
    document.title = folder.name + ' | Targets | ReconMind';
    const oldest = folder.scans[folder.scans.length - 1];
    const first = formatDay(oldest.started);
    refs.sub.textContent = (folder.kind === 'code' ? 'Source code. ' : '')
      + (first ? 'First scanned ' + first + '. ' : '') + plural(folder.scans.length, 'scan', 'scans') + ' so far.';
    refs.scanThis.textContent = folder.kind === 'code' ? 'Scan this code' : 'Scan this target';
    if (fromClick) {
      // Keep the address in step without remounting the view.
      history.replaceState(null, '', '#/targets/' + encodeURIComponent(folder.name));
    }
    renderPanel();
  }

  // ---- loading ---------------------------------------------------------

  function build(entries) {
    folders = group(entries);
    const { root, refs: r } = clone('tpl-targets');
    refs = r;
    view.replaceChildren(root);
    refs.folders.replaceChildren(...folders.map(folderButton));
    refs.filter.addEventListener('input', applyFilter);
    for (const btn of refs.tabs.querySelectorAll('[data-tab]')) {
      btn.addEventListener('click', () => {
        if (!TABS.includes(btn.dataset.tab)) return;
        tab = btn.dataset.tab;
        renderPanel();
      });
    }
    const start = folders.find((f) => f.name === wanted) || folders[0];
    select(start, false);
    // The indicator needs the real tab widths, known after layout.
    requestAnimationFrame(placeTabIndicator);
  }

  async function load() {
    let res;
    try {
      res = await api.get('/api/history');
    } catch (err) {
      res = { ok: false, status: 0, data: null };
    }
    if (!alive) return;
    if (res.status === 0) {
      showEmpty('The report history could not be loaded. The ReconMind server is not answering.');
      return;
    }
    if (!res.ok || !isObject(res.data) || !Array.isArray(res.data.entries)) {
      showEmpty('The report history could not be loaded. Reload to try again.');
      return;
    }
    const entries = res.data.entries.filter(isObject);
    if (!entries.length) {
      showEmpty(typeof res.data.warning === 'string' ? res.data.warning : null);
      return;
    }
    build(entries);
  }

  const onResize = () => { if (refs) placeTabIndicator(); };
  window.addEventListener('resize', onResize);
  load();
  return () => {
    alive = false;
    window.removeEventListener('resize', onResize);
  };
}
