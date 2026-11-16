/*
 * ReconMind API client.
 *
 * Every request sends "X-ReconMind: 1"; every POST sends a JSON body. The
 * server refuses a POST without both, and with no CORS another site cannot
 * add that header. Calls return {ok, status, data}; status 0 means the
 * server did not answer, and the banner under the top bar says so.
 */

import { serverDown } from './ui.js';

export const SERVER_DOWN = 'The ReconMind server is not answering. '
  + 'Check that python3 -m reconmind.web is still running.';

/*
 * opts.quiet: a failed request does not show the server banner. The Live run
 * check uses it, so a server that is down is not announced every 4 seconds.
 */
async function request(method, url, body, opts) {
  const quiet = !!(opts && opts.quiet);
  const init = {
    method,
    headers: { 'X-ReconMind': '1', Accept: 'application/json' },
    cache: 'no-store',
    credentials: 'same-origin',
  };
  if (method !== 'GET') {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body === undefined ? {} : body);
  }
  let response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    if (!quiet) serverDown(true);
    return { ok: false, status: 0, data: null, error: SERVER_DOWN };
  }
  serverDown(false);
  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }
  return { ok: response.ok, status: response.status, data };
}

export function get(url, opts) {
  return request('GET', url, undefined, opts);
}

export function post(url, body) {
  return request('POST', url, body);
}

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isText = (v) => typeof v === 'string';

/* True when /api/options has the shape the pages rely on. */
function validOptions(data) {
  if (!isObject(data) || !Array.isArray(data.presets) || !Array.isArray(data.actions)
      || !Array.isArray(data.allowlist) || !data.presets.length || !data.actions.length) {
    return false;
  }
  const okAction = (a) => isObject(a) && isText(a.id) && isText(a.name)
    && Array.isArray(a.tools) && a.tools.every(isText);
  const okPreset = (p) => isObject(p) && isText(p.id) && isText(p.ports)
    && Array.isArray(p.actions) && p.actions.every(isText);
  return data.actions.every(okAction) && data.presets.every(okPreset)
    && data.allowlist.every(isText);
}

/*
 * /api/options never changes while the server runs, so it is read once.
 * An answer without the expected shape counts as a failure (ok false), so
 * callers only ever see options they can use.
 */
let optionsCache = null;

export function options() {
  if (!optionsCache) {
    optionsCache = get('/api/options').then((res) => {
      if (res.ok && !validOptions(res.data)) {
        optionsCache = null;
        return { ok: false, status: res.status, data: null, invalid: true };
      }
      if (!res.ok) optionsCache = null; // try again next time
      return res;
    });
  }
  return optionsCache;
}
