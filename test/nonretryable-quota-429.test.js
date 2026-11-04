import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer, classify429 } from '../src/server.js';

// x-should-retry: false on a 429 is honoured only when the 429 is about the
// request (#555). A spent quota is still the account's verdict, and this
// fork's classifier names two quota shapes that carry no per-window status:
// a bare top-level `unified-status: rejected`, and a model bucket at its
// threshold. Both must rotate, not reach the client.

const listen = (server) => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const account = (name) => ({ name, type: 'oauth', accessToken: `t-${name}`, refreshToken: 'r', expiresAt: Date.now() + 3600_000 });
const reset = String(Math.floor(Date.now() / 1000) + 3 * 3600);

async function firstAccountRefuses(rejection, model) {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      seen.push(req.headers.authorization);
      if (req.headers.authorization === 'Bearer t-a') {
        res.writeHead(429, { 'content-type': 'application/json', ...rejection });
        res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'usage limit' } }));
      } else {
        res.writeHead(200, {
          'content-type': 'application/json',
          'anthropic-ratelimit-unified-status': 'allowed',
          'anthropic-ratelimit-unified-5h-utilization': '0.1',
          'anthropic-ratelimit-unified-5h-reset': reset,
        });
        res.end('{"ok":true}');
      }
    });
  });
  const am = new AccountManager(['a', 'b'].map(account), 0.98, { refreshFn: async () => { throw new Error('no refresh'); } });
  am.accounts[0].quota.unified5h = 0.2;
  am.accounts[1].quota.unified5h = 0.9; // a is the use-or-lose pick
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${await listen(upstream)}`, activeWarmup: false,
  });
  const port = await listen(proxy);
  const post = () => fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model, messages: [] }),
  });
  try {
    const first = await post();
    await first.text();
    const firstSeen = [...seen];
    seen.length = 0;
    const second = await post();
    await second.text();
    return { first: first.status, firstSeen, second: second.status, secondSeen: [...seen], reason: am.unavailableReason(am.accounts[0], model) };
  } finally {
    proxy.closeAllConnections();
    upstream.closeAllConnections();
    proxy.close();
    upstream.close();
  }
}

test('a no-retry 429 whose only quota verdict is the top-level unified status rotates', async () => {
  const rejection = {
    'x-should-retry': 'false', 'retry-after': '300',
    'anthropic-ratelimit-unified-status': 'rejected',
    'anthropic-ratelimit-unified-reset': reset,
    'anthropic-ratelimit-unified-5h-utilization': '1.0',
    'anthropic-ratelimit-unified-5h-reset': reset,
  };
  assert.equal(classify429(rejection, { model: 'claude-opus-4-5' }), 'account-quota');
  const r = await firstAccountRefuses(rejection, 'claude-opus-4-5');
  assert.equal(r.first, 200);
  assert.deepEqual(r.firstSeen, ['Bearer t-a', 'Bearer t-b']);
  assert.notEqual(r.reason, null, 'the spent account must leave rotation');
  assert.equal(r.second, 200);
  assert.deepEqual(r.secondSeen, ['Bearer t-b']);
});

test('a no-retry 429 on a model bucket at its threshold moves the request on', async () => {
  const rejection = {
    'x-should-retry': 'false', 'retry-after': '300',
    'anthropic-ratelimit-unified-status': 'rejected',
    'anthropic-ratelimit-unified-reset': reset,
    'anthropic-ratelimit-unified-7d_sonnet-status': 'rejected',
    'anthropic-ratelimit-unified-7d_sonnet-utilization': '1.01',
    'anthropic-ratelimit-unified-7d_sonnet-reset': reset,
    'anthropic-ratelimit-unified-5h-status': 'allowed',
    'anthropic-ratelimit-unified-5h-utilization': '0.3',
    'anthropic-ratelimit-unified-5h-reset': reset,
    'anthropic-ratelimit-unified-7d-status': 'allowed',
    'anthropic-ratelimit-unified-7d-utilization': '0.4',
  };
  assert.equal(classify429(rejection, { model: 'claude-sonnet-4-5' }), 'model-quota');
  const r = await firstAccountRefuses(rejection, 'claude-sonnet-4-5');
  assert.equal(r.first, 200);
  assert.deepEqual(r.firstSeen, ['Bearer t-a', 'Bearer t-b']);
  assert.equal(r.second, 200);
  assert.deepEqual(r.secondSeen, ['Bearer t-b']);
});
