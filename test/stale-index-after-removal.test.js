// A request's account can be removed while its request is upstream (a TUI
// delete, or a reload that drops an account gone from disk). The account
// manager renumbers the survivors, so a raw index taken before the await names
// whichever account moved into that slot. Everything that marks an account from
// the request path must pass the account object, which a removal makes stale
// instead of wrong.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

test('401 on an account removed mid-flight must not mark the account that inherited its index', async () => {
  let arrived; const arrivedP = new Promise((r) => { arrived = r; });
  let release; const releaseP = new Promise((r) => { release = r; });
  /** @type {string[]} */ const seen = [];
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', async () => {
      const key = String(req.headers['x-api-key'] || req.headers.authorization || '');
      seen.push(key);
      if (key === 'doomed-key') {
        arrived();
        await releaseP;
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'message', role: 'assistant', content: [] }));
    });
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([
    { name: 'doomed', type: 'apikey', apiKey: 'doomed-key' },
    { name: 'victim', type: 'oauth', accessToken: 'victim-token', refreshToken: 'victim-refresh', expiresAt: Date.now() + 3_600_000 },
    { name: 'spare', type: 'apikey', apiKey: 'spare-key' },
  ], 0.98);
  const [doomed, victim] = am.accounts;
  const original = { log: console.log, error: console.error };
  const lines = [];
  console.log = (...a) => lines.push(a.join(' '));
  console.error = (...a) => lines.push(a.join(' '));
  am.setDisabled(1, true);
  am.setDisabled(2, true);
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: {}, upstream: `http://127.0.0.1:${upstreamPort}` });
  const port = await listen(proxy);
  try {
    const pending = fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-test', max_tokens: 1, messages: [] }),
    });
    await arrivedP;                      // the request is on "doomed", upstream holding it
    am.setDisabled(1, false);
    am.setDisabled(2, false);
    am.removeAccount(0);                 // operator removes "doomed" (TUI delete / #465 reload drop)
    assert.equal(doomed.index, 0, 'precondition: the removed object keeps its stale index');
    assert.equal(am.accounts[0], victim, 'precondition: victim now sits at index 0');
    assert.equal(victim.status, 'active', 'precondition: victim healthy before the 401 lands');
    release();                           // upstream now answers 401 for "doomed"
    const res = await pending;
    await res.text();
    assert.equal(victim.status, 'active', 'victim must not be parked by another account\'s 401');
    assert.ok(!(victim.credentialRejectedUntil > Date.now()), 'nor held out by it');
    assert.ok(!lines.some(l => /"victim" (taken|held) out of rotation/.test(l)), 'and the log must not blame it');
  } finally {
    console.log = original.log;
    console.error = original.error;
    proxy.closeAllConnections?.(); proxy.close();
    upstream.closeAllConnections?.(); upstream.close();
  }
});
