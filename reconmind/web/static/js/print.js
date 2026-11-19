/*
 * Export PDF, matching docs/design/screens/10_PdfReport.html.
 *
 * printDocument(doc) builds a clean, light document from plain data, puts it
 * in #print-root and opens the system print dialog. Choose "Save as PDF" (a
 * browser) or "Print to File" (the ReconMind window) to get the PDF. On
 * screen nothing changes: the print stylesheet hides the app and shows only
 * #print-root, which is removed again after printing.
 *
 *   doc = {
 *     label: 'CONFIDENTIAL', title, subtitle,
 *     meta: [[label, value], ...],
 *     sections: [{ title, blocks: [
 *       { p: text } | { strong: text } | { pre: text } | { kv: [[label, value], ...] } |
 *       { table: { head: [...], rows: [[...], ...], sev: column index or -1 } } |
 *       { finding: { id, title, severity, kv: [[label, value]], parts: [[label, text]], evidence } }
 *     ] }],
 *     footer: text,
 *   }
 *
 * Every value is set with textContent; nothing is parsed as markup.
 */

import { h } from './ui.js';

const SEV = new Set(['critical', 'high', 'medium', 'low', 'info', 'none', 'unknown']);
const str = (v) => (v === null || v === undefined ? '' : String(v));

function sevChip(value) {
  const key = str(value).toLowerCase();
  return h('span', { class: 'pr-sev' + (SEV.has(key) ? ' pr-' + key : ''), text: key ? key[0].toUpperCase() + key.slice(1) : '' });
}

function block(b) {
  if ('p' in b) return h('p', { class: 'pr-p', text: str(b.p) });
  if ('strong' in b) return h('p', { class: 'pr-strong', text: str(b.strong) });
  if ('pre' in b) return h('pre', { class: 'pr-pre', text: str(b.pre) });
  if ('kv' in b) {
    return h('dl', { class: 'pr-kv' }, ...b.kv.filter((r) => str(r[1])).flatMap(([k, v]) => [
      h('dt', { text: str(k) }), h('dd', { text: str(v) })]));
  }
  if ('table' in b) {
    const t = b.table;
    return h('table', { class: 'pr-table' },
      h('thead', {}, h('tr', {}, ...t.head.map((c) => h('th', { text: str(c) })))),
      h('tbody', {}, ...t.rows.map((row) => h('tr', {}, ...row.map((c, i) => h('td', {},
        i === t.sev ? sevChip(c) : str(c)))))));
  }
  if ('finding' in b) {
    const f = b.finding;
    const parts = [h('div', { class: 'pr-fhead' }, h('span', { class: 'pr-fid', text: str(f.id) }),
      h('span', { class: 'pr-ftitle', text: str(f.title) }), sevChip(f.severity))];
    if (f.kv && f.kv.some((r) => str(r[1]))) parts.push(block({ kv: f.kv }));
    for (const [label, text] of f.parts || []) {
      if (str(text)) parts.push(h('p', { class: 'pr-p' }, h('b', { text: label + '. ' }), str(text)));
    }
    if (str(f.evidence)) parts.push(h('p', { class: 'pr-label', text: 'Evidence' }), h('pre', { class: 'pr-pre', text: str(f.evidence) }));
    return h('div', { class: 'pr-finding' }, ...parts);
  }
  return null;
}

export function buildDocument(doc) {
  const sections = (doc.sections || []).filter((s) => s && s.blocks && s.blocks.length);
  return h('article', { class: 'pr-doc' },
    h('header', { class: 'pr-cover' },
      h('div', { class: 'pr-brand' }, h('span', { text: 'ReconMind' }),
        doc.label ? h('span', { class: 'pr-label-tag', text: str(doc.label) }) : null),
      h('h1', { class: 'pr-title', text: str(doc.title) }),
      doc.subtitle ? h('p', { class: 'pr-sub', text: str(doc.subtitle) }) : null,
      doc.meta ? block({ kv: doc.meta }) : null),
    ...sections.map((s, i) => h('section', { class: 'pr-section' },
      h('h2', { class: 'pr-h2' }, h('span', { class: 'pr-num', text: String(i + 1) }), str(s.title)),
      ...s.blocks.map(block).filter(Boolean))),
    doc.footer ? h('footer', { class: 'pr-foot', text: str(doc.footer) }) : null);
}

export function printDocument(doc) {
  const old = document.getElementById('print-root');
  if (old) old.remove();
  const root = h('div', { id: 'print-root' }, buildDocument(doc));
  document.body.append(root);
  document.body.classList.add('printing');
  const title = document.title;
  document.title = str(doc.title).replace(/[\\/:*?"<>|]+/g, ' ').slice(0, 120) || title;
  const done = () => {
    document.body.classList.remove('printing');
    document.title = title;
    root.remove();
    window.removeEventListener('afterprint', done);
  };
  window.addEventListener('afterprint', done);
  // Let the layout settle before the dialog takes its snapshot.
  setTimeout(() => {
    try {
      window.print();
    } catch (err) {
      done();
    }
    // Some windows never send afterprint; clean up when the page is used again.
    setTimeout(() => { if (root.isConnected) window.addEventListener('focus', done, { once: true }); }, 500);
  }, 60);
}
