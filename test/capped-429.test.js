import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

// Incident 2026-09-25: a 10-account fleet had 7 accounts benched at 98-100% of
// their weekly quota and the other 3 holding 3 of 3 slots each. Clients were told
// `All 10 accounts are at their concurrency cap`, so the operator went looking for
// seven idle accounts that did not exist. In the same hour Claude Code's
// connectivity check waited behind inference for a slot: 215 of 263 checks failed,
// each one telling the client its network was down.

const HOUR = 3600_000;

function makeAccounts(n) {
  return Array.from({ length: n }, (_, i) => ({
    name: `a${i}`, type: 'oauth', accessToken: `tok-${i}`, refreshToken: 'r', expiresAt: Date.now() + HOUR,
  }));
}

function measure(am, index, util) {
  am.updateQuota(index, {
    'anthropic-ratelimit-unified-5h-utilization': String(util),
    'anthropic-ratelimit-unified-5h-reset': String(Math.floor((Date.now() + HOUR) / 1000)),
  });
}

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function okUpstream(seen = []) {
  return http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, authorization: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(req.method === 'HEAD' ? undefined : '{"ok":true}');
  });
}

test('the concurrency-cap 429 counts only the accounts at their cap and says why the rest cannot serve', async () => {
  const upstream = okUpstream();
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(makeAccounts(3), 0.98, 0, 1); // cap 1 per account
  measure(am, 0, 0.1);
  measure(am, 1, 0.99); // over the switch threshold
  measure(am, 2, 0.99);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    overflowQueueTimeoutMs: 0, // refuse instead of queueing, to reach the 429 directly
  });
  const port = await listen(proxy);

  try {
    const held = await am.acquireAccount(null, 0);
    assert.equal(held?.name, 'a0', 'precondition: the one available account holds its only slot');

    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST', body: '{"model":"claude-test"}',
    });
    const body = await res.json();
    am.releaseAccount(held);

    assert.equal(res.status, 429);
    const msg = body.error.message;
    assert.match(msg, /All 1 available account is at its concurrency cap/, msg);
    assert.match(msg, /the other 2 cannot serve claude-test \(quota: 2\)/, msg);
    assert.doesNotMatch(msg, /All 3/, `the two quota-benched accounts were counted as busy: ${msg}`);
    assert.equal(res.headers.get('retry-after'), '5');
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('the concurrency-cap 429 says when the overflow queue refused the wait', async () => {
  const upstream = okUpstream();
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(makeAccounts(1), 0.98, 0, 1, 1); // cap 1, queue depth 1
  measure(am, 0, 0.1);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    overflowQueueTimeoutMs: null, // wait until a slot frees: only a full queue refuses
  });
  const port = await listen(proxy);

  const held = await am.acquireAccount(null, 0);
  const waiter = am.acquireAccount(null, null); // takes the one queue position
  try {
    assert.ok(held, 'precondition: the only slot is held');
    assert.equal(am.isQueueFull(), true, 'precondition: the queue is full');

    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST', body: '{}', signal: AbortSignal.timeout(5000),
    });
    const body = await res.json();

    assert.equal(res.status, 429);
    assert.match(body.error.message, /concurrency cap, and the overflow queue is full \(1 waiting\)/, body.error.message);
  } finally {
    am.releaseAccount(held);
    const next = await waiter;
    if (next) am.releaseAccount(next);
    proxy.close();
    upstream.close();
  }
});

test('the connectivity check does not wait for an inference slot', async () => {
  const seen = [];
  const upstream = okUpstream(seen);
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(makeAccounts(1), 0.98, 0, 1); // cap 1
  measure(am, 0, 0.1);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    overflowQueueTimeoutMs: null, // an inference request would wait here forever
  });
  const port = await listen(proxy);

  const held = await am.acquireAccount(null, 0);
  try {
    assert.ok(held, 'precondition: the only slot is held');

    const res = await fetch(`http://127.0.0.1:${port}/api/hello`, {
      method: 'HEAD', signal: AbortSignal.timeout(3000),
    });

    assert.equal(res.status, 200, 'answered by upstream, not refused or queued');
    const hello = seen.find(r => r.url === '/api/hello');
    assert.ok(hello, 'the check reached upstream, so it still reports whether the API is reachable');
    assert.equal(hello.method, 'HEAD');
    assert.notEqual(hello.authorization, 'Bearer tok-0', 'no fleet token rides on a request that needs none');
    assert.equal(am.accounts[0].inflight, 1, 'no slot was taken');
  } finally {
    am.releaseAccount(held);
    proxy.close();
    upstream.close();
  }
});
