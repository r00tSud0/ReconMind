/*
 * Isolated, dependency-free DOM/API regression checks for System settings.
 * Run: node --experimental-default-type=module tests/test_system_ui_refinements.mjs
 * No network access, no real keys, no filesystem changes or scan execution.
 */
import assert from 'node:assert/strict';

class FakeNode {
  constructor(tag, plain = '') {
    this.tagName = tag;
    this.children = [];
    this.listeners = new Map();
    this.attrs = {};
    this._ownText = plain;
    this._className = '';
    this.value = '';
    this.placeholder = '';
    this.checked = false;
    this.disabled = false;
    this.style = { setProperty() {} };
    this.classList = {
      add: (name) => {
        const names = new Set(this._className.split(/\s+/).filter(Boolean));
        names.add(name); this._className = [...names].join(' ');
      },
      remove: (name) => { this._className = this._className.split(/\s+/).filter((x) => x !== name).join(' '); },
      toggle: (name, force) => {
        if (force) this.classList.add(name);
        else this.classList.remove(name);
        return !!force;
      },
      contains: (name) => this._className.split(/\s+/).includes(name),
    };
  }
  set className(value) { this._className = String(value); }
  get className() { return this._className; }
  set textContent(value) { this._ownText = String(value); this.children = []; }
  get textContent() { return this._ownText + this.children.map((x) => x.textContent).join(''); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes.filter((x) => x !== null); this._ownText = ''; }
  setAttribute(name, value) {
    this.attrs[name] = String(value);
    if (name === 'value') this.value = String(value);
    if (name === 'type') this.type = String(value);
    if (name === 'id') this.id = String(value);
    if (name === 'placeholder') this.placeholder = String(value);
    if (name === 'disabled') this.disabled = true;
  }
  addEventListener(name, callback) {
    const handlers = this.listeners.get(name) || [];
    handlers.push(callback);
    this.listeners.set(name, handlers);
  }
  trigger(name) {
    for (const handler of this.listeners.get(name) || []) handler();
  }
  find(predicate) {
    if (predicate(this)) return this;
    for (const item of this.children) {
      if (item instanceof FakeNode) {
        const match = item.find(predicate);
        if (match) return match;
      }
    }
    return null;
  }
}
globalThis.Node = FakeNode;
globalThis.document = {
  createElement: (tag) => new FakeNode(tag),
  createTextNode: (text) => new FakeNode('#text', String(text)),
  getElementById: () => null,
};

let current = {
  tools: [{name:'nmap', action:'Surface Map', status:'ready', version:'7.80', install:''}],
  ai: {provider:'openrouter', model:'openrouter/free', key_set:false, configured:false,
    custom_endpoint:false, providers:['openrouter','anthropic','huggingface','ollama']},
  mapper: {folder:'attack_mapper_run3', status:'files present',
    files_present:true, dependencies_present:true},
  nvd: {key_set:false}, safety:{allowlist:['10.10.1.0/24'],denylist:['10.10.3.0/24']},
  storage: {reports_folder:'reports',free_bytes: 3000000},
};
const requests = [];
let nextSaveFails = false;
globalThis.fetch = async (url, init) => {
  requests.push({url,method:init.method});
  if (url === '/api/system') {
    return {ok:true,status:200,json:async()=>structuredClone(current)};
  }
  if (url === '/api/system/test') {
    // Mimic test only: no settings changed.
    return {ok:true,status:200,json:async()=>({
      reachable:true,message:'Reachable. The provider accepted the test request.'})};
  }
  if (url === '/api/system/save') {
    if (nextSaveFails) {
      nextSaveFails = false;
      return {ok:false,status:400,json:async()=>({message:'Save was not permitted.'})};
    }
    const data = JSON.parse(init.body);
    current.ai.provider = data.provider;
    current.ai.model = data.model;
    if (data.api_key) current.ai.key_set = true;
    if (data.clear_api_key) current.ai.key_set = false;
    current.ai.configured = !!(current.ai.key_set && current.ai.model);
    if (data.nvd_key) current.nvd.key_set = true;
    if (data.clear_nvd_key) current.nvd.key_set = false;
    return {ok:true,status:200,json:async()=>({saved:true})};
  }
  throw new Error('Unexpected endpoint ' + url);
};
const {mountSystem} = await import('../reconmind/web/static/js/views/system.js');

const view = new FakeNode('main');
const unmount = mountSystem(view);
const settle = async()=>{for(let i=0;i<5;i++)await new Promise((resolve)=>setImmediate(resolve));};
await settle();
const byId = (id) => view.find((node)=>node.id === id);
const button = (name) => view.find((node)=>node.tagName==='button' && node.textContent===name);
const badge = (name) => view.find((node)=>
  node.classList.contains('sys-key-state') && node.textContent===name);
const feedback = ()=>view.find((node)=>node.classList.contains('sys-feedback'));

assert.equal(byId('sys-api-key').placeholder,'Enter an API key');
assert.equal(byId('sys-nvd-key').placeholder,'Optional NVD API key');
assert.ok(badge('Not saved'),'Initial badge explains that no key is saved');

byId('sys-api-key').value = 'test_dummy_secret_only';
button('Test connection').trigger('click');
await settle();
assert.equal(current.ai.key_set,false,'Connection test must not save a key');
assert.match(feedback().textContent,/Connection successful/);
assert.match(feedback().textContent,/No settings were saved/);

byId('sys-nvd-key').value = 'test_dummy_nvd_only';
button('Save settings').trigger('click');
await settle();
assert.equal(current.ai.key_set,true);
assert.equal(current.nvd.key_set,true);
assert.equal(byId('sys-api-key').value,'','Do not retain a secret in input after Save');
assert.equal(byId('sys-nvd-key').value,'','Do not retain NVD secret after Save');
assert.equal(byId('sys-api-key').placeholder,
  'Enter a new key only to replace the saved one');
assert.ok(badge('Saved'),'Saved key badge updates automatically');
assert.match(view.textContent,/LLM brain.*Configured/s,'AI card refreshes without Check again');
assert.match(view.textContent,/API key.*Key set/s,'API key card refreshes without Check again');
assert.match(feedback().textContent,/Settings saved/,'Feedback persists after card refresh');
assert.equal(requests.filter((r)=>r.url==='/api/system').length,2,
  'Only initial check and single automatic refresh; no unnecessary reloads');

byId('sys-provider').value = 'anthropic';
byId('sys-provider').trigger('change');
assert.equal(byId('sys-api-key').placeholder,'Enter a key for this provider if needed');
assert.ok(badge('Not checked'),'Changing providers does not claim another key is saved');

nextSaveFails = true;
button('Save settings').trigger('click');
await settle();
assert.match(feedback().textContent,/Save was not permitted/);
assert.equal(current.ai.provider,'openrouter');
unmount();
console.log('System UI refinements: all assertions passed.');
