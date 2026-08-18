import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function startProxy(am, upstreamPort, extraConfig = {}) {
  return createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false, // isolate 529 failover from background warm-up probes
    ...extraConfig,
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

test('configured Opus fallback retries once as Sonnet on the same account', async () => {
  const attempts = [];
  const upstream = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    attempts.push({
      authorization: req.headers.authorization,
      model: JSON.parse(Buffer.concat(chunks).toString()).model,
    });
    if (attempts.length === 1) {
      overloaded529(res, 1);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 'tok-a', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
    { name: 'b', type: 'oauth', accessToken: 'tok-b', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = startProxy(am, upstreamPort, { overloadFallbackModel: 'claude-sonnet-5' });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-opus-5[1m]', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 200);
    assert.deepEqual(attempts.map(a => a.model), ['claude-opus-5[1m]', 'claude-sonnet-5[1m]']);
    assert.equal(attempts[0].authorization, attempts[1].authorization,
      'model fallback must not fan out to another account');
    assert.ok(am.accounts.every(a => a.status !== 'throttled' && a.status !== 'error'),
      `expected no account poisoned, got ${am.accounts.map(a => a.status).join(',')}`);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('configured Opus fallback also recovers a pre-headers timeout', async () => {
  const models = [];
  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 'tok-a', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: 'https://unused.example',
    activeWarmup: false,
    overloadFallbackModel: 'claude-sonnet-5',
  }, {
    fetch: async (_url, options) => {
      const model = JSON.parse(options.body.toString()).model;
      models.push(model);
      if (models.length === 1) {
        const error = new Error('upstream response headers timed out after 10ms');
        error.code = 'TEAMCLAUDE_HEADERS_TIMEOUT';
        throw error;
      }
      return new globalThis.Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-opus-5', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 200);
    assert.deepEqual(models, ['claude-opus-5', 'claude-sonnet-5']);
  } finally {
    proxy.close();
  }
});

