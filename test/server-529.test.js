import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function startProxy(am, upstreamPort) {
  return createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false, // isolate 529 failover from background warm-up probes
  });
}

function overloaded529(res, retryAfter) {
  res.writeHead(529, {
    'content-type': 'application/json',
    ...(retryAfter == null ? {} : { 'retry-after': String(retryAfter) }),
  });
  res.end(JSON.stringify({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } }));
}

// 529 is Anthropic model capacity, not account health. Fan-out across accounts
// cannot recover it and composes disastrously with both proxy and Claude Code
// retry ladders, so one client attempt must make exactly one upstream attempt.
test('529 passes through once without account fan-out or account poisoning', async () => {
  let upstreamHits = 0;
  const upstream = http.createServer((_req, res) => {
    upstreamHits++;
    overloaded529(res, 1);
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 'tok-a', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
    { name: 'b', type: 'oauth', accessToken: 'tok-b', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = startProxy(am, upstreamPort);
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    const body = await res.json();
    assert.equal(res.status, 529);
    assert.equal(upstreamHits, 1);
    assert.equal(res.headers.get('retry-after'), '10');
    assert.match(body.error.message, /Retry in 10s/);
    assert.ok(am.accounts.every(a => a.status !== 'throttled' && a.status !== 'error'),
      `expected no account poisoned, got ${am.accounts.map(a => a.status).join(',')}`);
  } finally {
    proxy.close();
    upstream.close();
  }
});
// The no-fan-out rule is unconditional even when the legacy internal retry knob
// is set. A longer upstream retry deadline must survive the local 10-second floor.
test('529 ignores nested retry knob and preserves a longer upstream retry-after', async () => {
  process.env.TEAMCLAUDE_OVERLOAD_RETRIES = '2';

  let upstreamHits = 0;
  const upstream = http.createServer((_req, res) => {
    upstreamHits++;
    overloaded529(res, 30);
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 'tok-a', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
    { name: 'b', type: 'oauth', accessToken: 'tok-b', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = startProxy(am, upstreamPort);
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 529);
    assert.equal(upstreamHits, 1);
    assert.equal(res.headers.get('retry-after'), '30');
    assert.ok(am.accounts.every(a => a.status !== 'throttled' && a.status !== 'error'),
      `expected no account poisoned, got ${am.accounts.map(a => a.status).join(',')}`);
  } finally {
    proxy.close();
    upstream.close();
    delete process.env.TEAMCLAUDE_OVERLOAD_RETRIES;
  }
});

