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

async function request(method, url, body) {
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
    serverDown(true);
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

export function get(url) {
  return request('GET', url);
}

export function post(url, body) {
  return request('POST', url, body);
}

/* /api/options never changes while the server runs, so it is read once. */
let optionsCache = null;

export function options() {
  if (!optionsCache) {
    optionsCache = get('/api/options').then((res) => {
      if (!res.ok) optionsCache = null; // try again next time
      return res;
    });
  }
  return optionsCache;
}
