import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer, classify429, computeRetryAfter, parseRetryAfter } from '../src/server.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

// Drive one request through the proxy against an upstream that always 429s with
// the given Retry-After header, and report how the request terminated.
async function runAgainstThrottlingUpstream(retryAfterHeader) {
  let upstreamHits = 0;
  const upstream = http.createServer((_req, res) => {
    upstreamHits++;
    res.writeHead(429, { 'retry-after': retryAfterHeader, 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 }],
    0.98,
  );
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    await res.text();
    return {
      status: res.status, upstreamHits,
      accountStatus: am.accounts[0].status,
      paused: am.accounts[0].pausedUntil != null && am.accounts[0].pausedUntil > Date.now(),
    };
  } finally {
    proxy.close();
    upstream.close();
  }
}

test('429 classifier only accepts the current request governing model bucket', () => {
  const unrelated = {
    'anthropic-ratelimit-unified-status': 'rejected',
    'anthropic-ratelimit-unified-7d_unrelated-utilization': '1',
  };
  assert.equal(classify429(unrelated, { model: 'claude-fable-5' }), 'account-quota');

  const fable = {
    'anthropic-ratelimit-unified-status': 'rejected',
    'anthropic-ratelimit-unified-5h-utilization': '0.1',
    'anthropic-ratelimit-unified-7d_oi-utilization': '1',
  };
  assert.equal(classify429(fable, { model: 'claude-fable-5' }), 'model-quota');
  assert.equal(classify429(fable, { model: 'claude-sonnet-5' }), 'account-quota');
  assert.equal(classify429({
    ...fable,
    'anthropic-ratelimit-unified-5h-status': 'rejected',
  }, { model: 'claude-fable-5' }), 'account-quota');
});
test('server classifies 429s from current model/advisor headers before sx observes residuals', async () => {
  const events = [];
  const sx = {
    useByDefault: () => false,
    useOn429: () => true,
    noteRateLimited: () => events.push('sx'),
  };
  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  // A retained rejection must never turn a later headerless 429 into account quota.
  am.accounts[0].quota.unifiedStatus = 'rejected';
  const updateQuota = am.updateQuota.bind(am);
  am.updateQuota = (account, headers) => {
    events.push(`quota:${headers['anthropic-ratelimit-unified-status'] || 'none'}`);
    return updateQuota(account, headers);
  };
  const proxy = createProxyServer(am, { proxy: { apiKey: 'k' }, upstream: 'http://upstream.invalid' }, {
    fetch: async (_url, options) => {
      const body = options.body.toString();
      const advisorRequest = body.includes('"advisor_20260301"');
      return new globalThis.Response(JSON.stringify({ type: 'error' }), {
        status: 429,
        headers: advisorRequest
          ? {
            'retry-after': '60',
            'anthropic-ratelimit-unified-status': 'rejected',
            'anthropic-ratelimit-unified-7d_oi-utilization': '1',
          }
          : { 'retry-after': '60' },
      });
    },
  }, sx);
  const proxyPort = await listen(proxy);
  try {
    const send = body => fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });

    const modelQuota = await send({
      model: 'claude-other-5',
      tools: [{ type: 'advisor_20260301', name: 'advisor', model: 'claude-fable-5' }],
      messages: [],
    });
    await modelQuota.text();
    assert.equal(modelQuota.status, 429);
    assert.deepEqual(events, ['quota:rejected'],
      'the advisor-governing model bucket classifies this response as model quota, not sx residual');

    const transient = await send({ model: 'claude-other-5', messages: [] });
    await transient.text();
    assert.equal(transient.status, 429);
    assert.equal(events.indexOf('quota:none') < events.indexOf('sx'), true,
      'quota mutation precedes sx observation for the current residual response');
    assert.equal(events.filter(event => event === 'sx').length, 1,
      'stale rejected quota does not poison a later transient 429 classification');
    assert.equal(am.accounts[0].status, 'active', 'residual 429 does not globally throttle the account');
  } finally {
    proxy.close();
  }
});

test('Retry-After parser accepts one integer or HTTP-date and rejects malformed values', () => {
  const now = Date.UTC(2026, 6, 22, 12, 0, 0);
  assert.equal(parseRetryAfter('42', now), 42);
  assert.equal(parseRetryAfter('0', now), 1);
  assert.equal(parseRetryAfter('-1', now), 1);
  assert.equal(parseRetryAfter('Wed, 22 Jul 2026 11:59:30 GMT', now), 1);
  assert.equal(parseRetryAfter('Wed, 22 Jul 2026 12:00:30 GMT', now), 30);
  assert.equal(parseRetryAfter('1, 2', now), 60);
  assert.equal(parseRetryAfter('999999', now), 300);
  assert.equal(parseRetryAfter('garbage', now), 60);
});

test('only trusted local all-exhausted reset guidance may exceed 300 seconds', () => {
  const now = Date.UTC(2026, 6, 22, 12, 0, 0);
  const accountAt = seconds => ({
    enabled: true,
    status: 'active',
    quota: {
      unified5h: 1,
      unified5hReset: now + seconds * 1000,
    },
  });

  assert.equal(computeRetryAfter([accountAt(301)], 0.98, now), 301);
  assert.equal(computeRetryAfter([accountAt(3600)], 0.98, now), 3600);
  assert.equal(computeRetryAfter([accountAt(10_800)], 0.98, now), 10_800);
  assert.equal(parseRetryAfter('301', now), 300, 'upstream/residual delay remains bounded');
  assert.equal(parseRetryAfter('3600', now), 300, 'pause/sx input remains bounded');
});

// Regression: a persistently rate-limited upstream must terminate (bounded
// retries), not loop forever tying up the client connection. A rate-limit 429
// does NOT rotate/throttle the account (#84) — it pauses it (so concurrent
// requests wait) and retries the same account, then surfaces a 429.
test('persistent upstream 429 terminates with a bounded number of retries', async () => {
  const { status, upstreamHits, accountStatus, paused } = await runAgainstThrottlingUpstream('1');
  assert.equal(status, 429);                                   // returns 429 instead of hanging
  assert.ok(upstreamHits >= 1 && upstreamHits <= 4, `expected bounded retries, got ${upstreamHits}`);
  assert.equal(accountStatus, 'active');                       // NOT throttled — no rotation on a rate-limit 429
  assert.ok(paused, 'account should be paused, so concurrent requests wait');
});

// A negative (or otherwise out-of-range) Retry-After must not bypass the cap:
// it would make setTimeout return immediately (and previously mark the account
// rate-limited in the past, reactivating it instantly).
test('negative Retry-After is clamped and still terminates', async () => {
  const { status, upstreamHits, accountStatus, paused } = await runAgainstThrottlingUpstream('-1');
  assert.equal(status, 429);
  assert.ok(upstreamHits >= 1 && upstreamHits <= 4, `expected bounded retries, got ${upstreamHits}`);
  assert.equal(accountStatus, 'active');
  assert.ok(paused);
});

test('long upstream Retry-After is surfaced without sleeping in client request', async () => {
  let upstreamHits = 0;
  const upstream = http.createServer((_req, res) => {
    upstreamHits++;
    res.writeHead(429, { 'retry-after': '300', 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 }],
    0.98,
  );
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const started = Date.now();
    let res;
    try {
      res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'x', messages: [] }),
        signal: AbortSignal.timeout(2000),
      });
    } catch (err) {
      assert.fail(`request should return 429 promptly, got ${err.name}`);
    }

    await res.text();
    assert.equal(res.status, 429);
    assert.equal(upstreamHits, 1, 'long Retry-After should not be retried inline');
    assert.ok(Date.now() - started < 2000, 'request should not sleep for upstream retry window');
    assert.equal(am.accounts[0].status, 'active', 'rate-limit 429 must not throttle/rotate the account');
    assert.ok(am.accounts[0].pausedUntil > Date.now(), 'account should be paused so concurrent requests wait');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// A residual 429 cannot poison quota state, but after its same-identity egress
// attempt is unavailable it spills this request to the next eligible account.
test('a residual 429 spills accounts in bounded order when sx is unavailable', async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push(req.headers.authorization);
    res.writeHead(429, { 'retry-after': '1', 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 't-a', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
    { name: 'b', type: 'oauth', accessToken: 't-b', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = createProxyServer(am, { proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 429);
    assert.deepEqual(seen, ['Bearer t-a', 'Bearer t-b'], 'each eligible account is tried once');
    assert.ok(am.accounts.every(account => account.pausedUntil > Date.now()),
      'residual attempts pause only the accounts that actually returned 429');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// A quota-rejection 429 (unified status "rejected") is durable exhaustion, so it
// DOES rotate — account a is throttled and the request succeeds on account b.
test('a quota-rejection 429 rotates to the next account', async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push(req.headers.authorization);
    if (req.headers.authorization === 'Bearer t-a') {
      res.writeHead(429, {
        'retry-after': '60',
        'anthropic-ratelimit-unified-5h-status': 'rejected',
        'content-type': 'application/json',
      });
      res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error' } }));
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'message', role: 'assistant', content: [] }));
    }
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 't-a', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
    { name: 'b', type: 'oauth', accessToken: 't-b', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = createProxyServer(am, { proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 200, 'should succeed on the second account');
    assert.equal(am.accounts[0].status, 'throttled', 'exhausted account is throttled (rotated away)');
    assert.ok(seen.includes('Bearer t-b'), 'request rotated to account b');
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('temporarily exhausted fleet waits and retries instead of surfacing synthetic 429', async () => {
  let upstreamHits = 0;
  const upstream = http.createServer((_req, res) => {
    upstreamHits++;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'message', role: 'assistant', content: [] }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 }],
    0.98,
  );
  am.markRateLimited(0, 1);

  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const started = Date.now();
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    const text = await res.text();

    assert.equal(res.status, 200, text);
    assert.equal(upstreamHits, 1, 'request should reach upstream after throttle expires');
    assert.ok(Date.now() - started >= 900, 'request should wait for retry window');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// `holdMs` is the only thing that lets a request keep waiting once `retryCount` has
// reached `maxRetries` (= accounts.length), and it also caps how long the
// throttle-recovery sleep may be: min(throttleWait + THROTTLE_WAKE_MARGIN_MS,
// holdRemaining). Nothing in the suite referenced holdMs at all, so both halves of that
// expression were uncovered while a fix was being made to it. Note what this does NOT
// pin: the 5ms margin is far below timing resolution here, so this proves the hold is
// respected as a ceiling, not that the margin is excluded from it.
test('holdMs extends the retry budget past maxRetries and caps the throttle wait', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'message', role: 'assistant', content: [] }));
  });
  const upstreamPort = await listen(upstream);
  const acct = () => [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 }];
  const post = port => fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'x', messages: [] }),
  });

  // Hold longer than the throttle → the request rides the throttle out and succeeds.
  const amLong = new AccountManager(acct(), 0.98);
  amLong.markRateLimited(0, 0.2);
  const proxyLong = createProxyServer(amLong, {
    proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}`, holdMs: 3000,
  });
  const portLong = await listen(proxyLong);

  // Hold SHORTER than the throttle → give up when the hold runs out, not 30s later.
  const amShort = new AccountManager(acct(), 0.98);
  amShort.markRateLimited(0, 30);
  const proxyShort = createProxyServer(amShort, {
    proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}`, holdMs: 150,
  });
  const portShort = await listen(proxyShort);

  try {
    const t1 = Date.now();
    const rLong = await post(portLong);
    await rLong.text();
    assert.equal(rLong.status, 200, 'a hold longer than the throttle must let the request through');
    assert.ok(Date.now() - t1 >= 190, 'and it must actually wait the throttle out, not fail fast');

    const t2 = Date.now();
    const rShort = await post(portShort);
    await rShort.text();
    const waited = Date.now() - t2;
    assert.equal(rShort.status, 429, 'a hold shorter than the throttle must give up');
    assert.ok(waited < 2000, `the hold, not the 30s throttle, must cap the wait: waited ${waited}ms`);
  } finally {
    proxyLong.close();
    proxyShort.close();
    upstream.close();
  }
});

// Regression for #46: a stale/poisoned cached quota (e.g. 0.98 from before a
// plan upgrade, with a reset still in the future) must NOT pin the proxy in a
// permanent synthetic 429. The next request should probe upstream, succeed, and
// refresh the cached quota — rather than refusing locally without any call.
test('stale over-threshold quota is re-probed, not refused forever', async () => {
  let upstreamHits = 0;
  const upstream = http.createServer((_req, res) => {
    upstreamHits++;
    res.writeHead(200, {
      'content-type': 'application/json',
      // Real headroom: the upgraded account is nowhere near its limit.
      'anthropic-ratelimit-unified-7d-utilization': '0.10',
    });
    res.end(JSON.stringify({ type: 'message', role: 'assistant', content: [] }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 }],
    0.98,
  );
  // Simulate restoring a poisoned snapshot from teamclaude.state.json.
  am.importQuotaState([
    { name: 'a', quota: { unified7d: 0.98, unified7dReset: Date.now() + 7 * 24 * 3600_000 } },
  ]);

  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 200, 'request should be proxied, not refused with a synthetic 429');
    assert.equal(upstreamHits, 1, 'a real upstream probe should have been made');
    assert.equal(am.accounts[0].quota.unified7d, 0.10, 'cached quota should be refreshed from the probe');
  } finally {
    proxy.close();
    upstream.close();
  }
});
// A utilization-only model-tier rejection must not globally throttle healthy
// shared account quota. This is the fork regression fixture retained verbatim.
test('model-scoped exhaustion fails over once without poisoning other model traffic', async () => {
  let fableHits = 0;
  let otherHits = 0;
  const reset = String(Math.floor((Date.now() + 24 * 3600_000) / 1000));
  const upstream = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const model = JSON.parse(Buffer.concat(chunks).toString()).model;
    if (model === 'fable') {
      fableHits++;
      res.writeHead(429, {
        'retry-after': '300',
        'anthropic-ratelimit-unified-status': 'rejected',
        'anthropic-ratelimit-unified-5h-utilization': '0.12',
        'anthropic-ratelimit-unified-5h-reset': reset,
        'anthropic-ratelimit-unified-7d-utilization': '0.69',
        'anthropic-ratelimit-unified-7d-reset': reset,
        'anthropic-ratelimit-unified-7d_oi-utilization': '1.01',
        'anthropic-ratelimit-unified-7d_oi-reset': reset,
        'content-type': 'application/json',
      });
      res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error' } }));
      return;
    }
    otherHits++;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 'tok-a', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
    { name: 'b', type: 'oauth', accessToken: 'tok-b', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);
  try {
    const send = model => fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model, messages: [] }),
    });
    const rejected = await send('fable');
    await rejected.text();
    assert.equal(rejected.status, 429);
    assert.equal(fableHits, 2, 'model request tried each account once');
    assert.ok(am.accounts.every(a => a.status === 'active'),
      'model exhaustion must not globally throttle any account');

    const accepted = await send('other');
    await accepted.text();
    assert.equal(accepted.status, 200);
    assert.equal(otherHits, 1, 'unrelated model remains immediately routable');
  } finally {
    proxy.close();
    upstream.close();
  }
});
