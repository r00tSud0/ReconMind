/*
 * System check (#/system), matching 08_System.html.
 * Status comes from the real tool resolvers and read-only server config.
 * No user- or server-provided text is parsed as HTML.
 */
import * as api from '../api.js';
import { h } from '../ui.js';

const asObject = (x) => x && typeof x === 'object' && !Array.isArray(x) ? x : {};
const asList = (x) => Array.isArray(x) ? x : [];
const label = (value) => value === null || value === undefined ? '' : String(value);

function status(text, good) {
  return h('span', { class: 'sys-status' + (good ? ' good' : ''), text });
}
function row(name, detail, state, good) {
  return h('div', { class: 'sys-row' },
    h('div', { class: 'sys-row-id' },
      h('strong', { text: label(name) }),
      h('span', { class: 'help', text: label(detail) })),
    status(label(state), good));
}
const MAPPER_STATES = {
  'files present': 'Files present',
  'dependencies missing': 'Dependencies missing',
  'model missing': 'Model missing',
};
function section(title, ...contents) {
  return h('section', { class: 'glass sys-panel reveal' },
    h('h2', { class: 'h2', text: title }), ...contents);
}

function aiRows(ai, mapper) {
  return [
    row('LLM brain', (ai.provider || 'No provider') + (ai.model ? ' · ' + ai.model : ''),
      ai.configured ? 'Configured' : 'Needs setup', !!ai.configured),
    row('API key', 'Only key status is shown. The key is never returned by this page.',
      ai.key_set ? 'Key set' : 'No key', !!ai.key_set),
    ai.custom_endpoint ? h('p', { class: 'help',
      text: 'A custom AI endpoint is active. The web connection test is disabled '
        + 'for custom addresses to protect your key.' }) : null,
    row('ATT&CK mapper', 'Model folder: ' + (mapper.folder || 'unknown')
      + '. This checks files and dependencies, not live inference.',
      MAPPER_STATES[mapper.status] || 'Unknown', mapper.files_present && mapper.dependencies_present),
  ];
}
function nvdRows(nvd) {
  return [row('NVD API', 'A key improves request limits. The scan can use NVD without one.',
    nvd.key_set ? 'Key set' : 'No API key', !!nvd.key_set)];
}

/* A successful connection test never saves credentials; only Save does. */
function settingsPanel(initialAI, initialNVD, afterSave) {
  let savedAI = asObject(initialAI);
  let savedNVD = asObject(initialNVD);
  const providers = asList(savedAI.providers);
  const provider = h('select', { class: 'field', id: 'sys-provider' },
    ...providers.map((name) => h('option', { value: name, text: name })));
  provider.value = providers.includes(savedAI.provider) ? savedAI.provider : providers[0];
  const model = h('input', { class: 'field', type: 'text', id: 'sys-model',
    maxlength: '180', value: savedAI.model || '', placeholder: 'Model identifier' });
  const apiKey = h('input', { class: 'field', type: 'password', id: 'sys-api-key',
    maxlength: '8192', autocomplete: 'new-password' });
  const nvdKey = h('input', { class: 'field', type: 'password', id: 'sys-nvd-key',
    maxlength: '8192', autocomplete: 'new-password' });
  const removeAI = h('input', { type: 'checkbox', id: 'sys-remove-ai' });
  const removeNVD = h('input', { type: 'checkbox', id: 'sys-remove-nvd' });
  const save = h('button', { class: 'btn primary', type: 'button', text: 'Save settings' });
  const test = h('button', { class: 'btn quiet', type: 'button', text: 'Test connection' });
  const feedback = h('p', { class: 'sys-feedback help', role: 'status',
    'aria-live': 'polite', text: 'Test connection checks the provider. Save settings applies your changes.' });
  const field = (title, control) => h('div', { class: 'sys-setting-field' },
    h('label', { class: 'label', for: control.id, text: title }), control);
  const check = (control, text) => h('label', { class: 'sys-check' }, control,
    h('span', { text }));
  const aiState = h('span', { class: 'sys-key-state', text: '' });
  const nvdState = h('span', { class: 'sys-key-state', text: '' });
  const aiHelp = h('p', { class: 'help sys-secret-help' });
  const nvdHelp = h('p', { class: 'help sys-secret-help' });
  const secretField = (title, control, state, help) => h('div',
    { class: 'sys-setting-field' },
    h('div', { class: 'sys-field-head' },
      h('label', { class: 'label', for: control.id, text: title }), state),
    control, help);

  function updateKeyDisplay() {
    const local = provider.value === 'ollama';
    const sameProvider = provider.value === savedAI.provider;
    if (local) {
      aiState.textContent = 'Not required';
      apiKey.placeholder = 'No API key needed for Ollama';
      aiHelp.textContent = 'This provider does not require an API key.';
      apiKey.disabled = true;
    } else {
      apiKey.disabled = false;
      if (!sameProvider) {
        aiState.textContent = 'Not checked';
        apiKey.placeholder = 'Enter a key for this provider if needed';
        aiHelp.textContent = 'Saved-key status is shown for the currently configured provider. '
          + 'Save to check this provider.';
      } else if (savedAI.key_set) {
        aiState.textContent = 'Saved';
        apiKey.placeholder = 'Enter a new key only to replace the saved one';
        aiHelp.textContent = 'Your existing key is saved and never displayed. '
          + 'Leave this field empty to keep it.';
      } else {
        aiState.textContent = 'Not saved';
        apiKey.placeholder = 'Enter an API key';
        aiHelp.textContent = 'No key is saved for the current provider.';
      }
    }
    nvdState.textContent = savedNVD.key_set ? 'Saved' : 'Not saved';
    nvdKey.placeholder = savedNVD.key_set
      ? 'Enter a new key only to replace the saved one' : 'Optional NVD API key';
    nvdHelp.textContent = savedNVD.key_set
      ? 'Your existing NVD key is saved. Leave this field empty to keep it.'
      : 'Optional: NVD requests also work without an API key.';
  }

  const panel = section('Settings',
    field('AI provider', provider), field('Model', model),
    secretField('AI API key', apiKey, aiState, aiHelp),
    check(removeAI, 'Remove saved AI key for this provider'),
    secretField('NVD API key', nvdKey, nvdState, nvdHelp),
    check(removeNVD, 'Remove saved NVD key'),
    h('p', { class: 'help', text: 'Test connection sends one small request '
      + 'without saving settings or starting a scan.' }),
    h('div', { class: 'sys-setting-actions' }, test, save), feedback);

  updateKeyDisplay();
  provider.addEventListener('change', () => {
    model.value = '';
    removeAI.checked = false;
    apiKey.value = '';
    updateKeyDisplay();
  });
  apiKey.addEventListener('input', () => { if (apiKey.value) removeAI.checked = false; });
  nvdKey.addEventListener('input', () => { if (nvdKey.value) removeNVD.checked = false; });
  removeAI.addEventListener('change', () => { if (removeAI.checked) apiKey.value = ''; });
  removeNVD.addEventListener('change', () => { if (removeNVD.checked) nvdKey.value = ''; });

  let busy = false;
  async function send(type) {
    if (busy) return;
    busy = true;
    save.disabled = true; test.disabled = true;
    feedback.classList.remove('bad');
    feedback.textContent = type === 'save' ? 'Saving settings…' : 'Testing connection…';
    try {
      const res = await api.post(type === 'save' ? '/api/system/save' : '/api/system/test',
        { provider: provider.value, model: model.value.trim(),
          api_key: apiKey.value, nvd_key: nvdKey.value,
          clear_api_key: removeAI.checked, clear_nvd_key: removeNVD.checked });
      if (!res.ok || (type === 'save' && (!res.data || res.data.saved !== true))) {
        feedback.classList.add('bad');
        feedback.textContent = res.data && res.data.message
          ? label(res.data.message) : 'The settings request failed.';
      } else if (type === 'save') {
        apiKey.value = ''; nvdKey.value = '';
        removeAI.checked = false; removeNVD.checked = false;
        api.invalidateOptions();
        // Refresh only status sections; never replace this form or lose its feedback.
        const updated = await afterSave();
        if (updated) {
          savedAI = asObject(updated.ai);
          savedNVD = asObject(updated.nvd);
          updateKeyDisplay();
          feedback.textContent = 'Settings saved. AI and key statuses updated. '
            + 'New scans will use these settings.';
        } else {
          feedback.textContent = 'Settings saved, but the status could not refresh. '
            + 'Select Check again to update the status panels.';
        }
      } else if (res.data && res.data.reachable === true) {
        feedback.textContent = 'Connection successful. No settings were saved. '
          + 'Select Save settings to apply these values.';
      } else {
        feedback.classList.add('bad');
        feedback.textContent = res.data && res.data.message
          ? 'Connection unsuccessful. ' + label(res.data.message)
          : 'The connection result was unavailable. No settings were saved.';
      }
    } catch (err) {
      feedback.classList.add('bad');
      feedback.textContent = 'The request could not be completed. '
        + 'Check the local server and try again.';
    } finally {
      busy = false;
      save.disabled = false; test.disabled = false;
    }
  }
  save.addEventListener('click', () => { send('save'); });
  test.addEventListener('click', () => { send('test'); });
  return panel;
}

export function mountSystem(view) {
  let alive = true;
  const root = h('main', { class: 'page page-wide system-page' });
  const title = h('h1', { class: 'title', text: 'System check' });
  const summary = h('p', { class: 'help', text: 'Checking the tools and settings ReconMind uses.' });
  const reload = h('button', { class: 'btn quiet', type: 'button', text: 'Check again' });
  // Setup installs or repairs tools; System itself only reports.
  const setupLink = h('a', { class: 'btn quiet', href: '#/setup', text: 'Setup' });
  const head = h('header', { class: 'sys-header' },
    h('div', {}, title, summary),
    h('div', { class: 'sys-setting-actions setup-actions' }, setupLink, reload));
  const body = h('div', { class: 'system-grid' });
  root.append(head, body);
  view.append(root);

  async function load() {
    reload.disabled = true;
    summary.textContent = 'Checking installed tools and configuration.';
    const res = await api.get('/api/system');
    if (!alive) return;
    reload.disabled = false;
    if (!res.ok || !res.data || typeof res.data !== 'object') {
      summary.textContent = res.status === 0
        ? 'The ReconMind server is not answering.'
        : 'The system check could not be loaded.';
      body.replaceChildren(section('System unavailable',
        h('p', { class: 'help', text: 'Use Check again after the server is running.' })));
      return;
    }
    const d = res.data;
    const tools = asList(d.tools);
    const ready = tools.filter((t) => t.status === 'ready').length;
    summary.textContent = ready + ' of ' + tools.length
      + ' security tools detected in this environment.';
    const mapperReady = asObject(d.mapper).files_present && asObject(d.mapper).dependencies_present;
    const needsRepair = ready < tools.length || !mapperReady;
    setupLink.textContent = needsRepair ? 'Repair setup' : 'Setup';
    setupLink.className = needsRepair ? 'btn primary' : 'btn quiet';
    const ai = asObject(d.ai);
    const mapper = asObject(d.mapper);
    const nvd = asObject(d.nvd);
    const safety = asObject(d.safety);
    const storage = asObject(d.storage);
    const toolsPanel = section('Security tools',
      h('p', { class: 'help', text: 'Readiness checks for the tools used by the scanning engine.' }),
      ...tools.map((t) => row(t.name, t.action + (t.version ? ' · ' + t.version : ''),
        t.status === 'ready' ? 'Ready' : 'Missing', t.status === 'ready')));
    const aiPanel = section('AI', ...aiRows(ai, mapper));
    const nvdPanel = section('NVD', ...nvdRows(nvd));
    async function refreshAfterSave() {
      const updated = await api.get('/api/system');
      if (!alive || !updated.ok || !updated.data
          || typeof updated.data !== 'object' || !updated.data.ai || !updated.data.nvd) {
        return null;
      }
      const latestAI = asObject(updated.data.ai);
      const latestMapper = asObject(updated.data.mapper);
      const latestNVD = asObject(updated.data.nvd);
      aiPanel.replaceChildren(h('h2', { class: 'h2', text: 'AI' }),
        ...aiRows(latestAI, latestMapper));
      nvdPanel.replaceChildren(h('h2', { class: 'h2', text: 'NVD' }),
        ...nvdRows(latestNVD));
      return { ai: latestAI, nvd: latestNVD };
    }
    const safetyPanel = section('Safety',
      row('Authorization gate', 'The application cannot change allowed or blocked networks.',
        'Scope locked', true),
      h('h3', { class: 'sys-subhead', text: 'Allowed networks' }),
      h('div', { class: 'sys-networks' },
        ...asList(safety.allowlist).map((network) => h('span', { class: 'sys-network', text: label(network) }))),
      h('h3', { class: 'sys-subhead', text: 'Always blocked' }),
      h('div', { class: 'sys-networks' },
        ...asList(safety.denylist).map((network) =>
          h('span', { class: 'sys-network blocked', text: label(network) }))));
    const free = typeof storage.free_bytes === 'number'
      ? (storage.free_bytes / (1024 ** 3)).toFixed(1) + ' GiB free' : 'Space unavailable';
    const storagePanel = section('Storage',
      row('Reports', 'Saved in ' + (storage.reports_folder || 'reports') + '/', free, true));
    body.replaceChildren(toolsPanel,
      h('div', { class: 'sys-stack' },
        aiPanel, nvdPanel, settingsPanel(ai, nvd, refreshAfterSave), safetyPanel, storagePanel));
  }
  reload.addEventListener('click', load);
  load();
  return () => { alive = false; };
}
