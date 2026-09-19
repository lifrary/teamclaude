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
    activeWarmup: false, proxy: { apiKey: 'k' },
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
test('429 classifier resolves numeric thresholds separately for model and advisor buckets', () => {
  const headers = {
    'anthropic-ratelimit-unified-status': 'rejected',
    'anthropic-ratelimit-unified-7d_oi-utilization': '0.85',
    'anthropic-ratelimit-unified-7d_sonnet-utilization': '0.7',
  };
  const switchThreshold = { default: 0.98, unified7dFable: 0.8, unified7dSonnet: 0.9 };
  assert.equal(classify429(headers, { model: 'claude-fable-5', switchThreshold }), 'model-quota');
  assert.equal(classify429(headers, { model: 'claude-sonnet-5', switchThreshold }), 'account-quota');
  assert.equal(classify429(headers, {
    model: 'claude-sonnet-5', advisorModel: 'claude-fable-5', switchThreshold,
  }), 'model-quota');
  assert.equal(classify429(headers, {
    model: 'claude-fable-5', switchThreshold: { default: 0.9 },
  }), 'account-quota');
  for (const threshold of [0.98, { default: 0.98 }, { session: 0.98, weekly: 0.98, models: 0.98 }]) {
    assert.equal(classify429({
      ...headers, 'anthropic-ratelimit-unified-7d_oi-utilization': '1',
    }, { model: 'claude-fable-5', switchThreshold: threshold }), 'model-quota');
  }
});

test('server classifies 429s from current model/advisor headers before sx observes residuals', { timeout: 4000 }, async () => {
  const events = [];
  let transientReached, releaseTransient;
  const dispatched = new Promise(resolve => { transientReached = resolve; });
  const held = new Promise(resolve => { releaseTransient = resolve; });
  const sx = {
    useByDefault: () => false,
    useOn429: () => true,
    noteRateLimited: () => events.push('sx'),
  };
  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], { default: 0.98, unified7dFable: 0.95 });
  // Both requests dispatch while eligible. The model-quota response then lands
  // before the residual response, establishing a real retained rejection.
  // No spending probe may bypass the exhausted account to set up this race.
  const updateQuota = am.updateQuota.bind(am);
  am.updateQuota = (account, headers) => {
    events.push(`quota:${headers['anthropic-ratelimit-unified-status'] || 'none'}`);
    return updateQuota(account, headers);
  };
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: 'http://upstream.invalid' }, {
    fetch: async (_url, options) => {
      const body = options.body.toString();
      const advisorRequest = body.includes('"advisor_20260301"');
      if (!advisorRequest) {
        transientReached();
        await held;
      }
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

    const transientResponse = send({ model: 'claude-other-5', messages: [] });
    await dispatched;
    const modelQuota = await send({
      model: 'claude-other-5',
      tools: [{ type: 'advisor_20260301', name: 'advisor', model: 'claude-fable-5' }],
      messages: [],
    });
    await modelQuota.text();
    assert.equal(modelQuota.status, 429);
    assert.deepEqual(events, ['quota:rejected'],
      'the advisor-governing model bucket classifies this response as model quota, not sx residual');
    assert.equal(am.accounts[0].status, 'active', 'object thresholds must not throttle every model');
    assert.equal(am.accounts[0].rateLimitedUntil, null);
    assert.equal(am.accounts[0].quota.unifiedStatus, 'rejected', 'the residual arrives after a real retained rejection');

    releaseTransient();
    const transient = await transientResponse;
    await transient.text();
    assert.equal(transient.status, 429);
    assert.equal(events.indexOf('quota:none') < events.indexOf('sx'), true,
      'quota mutation precedes sx observation for the current residual response');
    assert.equal(events.filter(event => event === 'sx').length, 1,
      'stale rejected quota does not poison a later transient 429 classification');
    assert.equal(am.accounts[0].status, 'active', 'residual 429 does not globally throttle the account');
  } finally {
    releaseTransient();
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

test('headerless request-scoped 429 never pauses the fleet or invents Retry-After', async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push(req.headers.authorization);
    res.writeHead(429, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'Unsupported request model' } }));
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(['a', 'b', 'c'].map(name => ({
    name, type: 'oauth', accessToken: `t-${name}`, expiresAt: Date.now() + 3600_000,
  })), 0.98);
  const proxy = createProxyServer(am, {
    activeWarmup: false, upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const port = await listen(proxy);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'unsupported', messages: [] }),
      signal: AbortSignal.timeout(2000),
    });
    assert.equal(res.status, 429);
    assert.equal(res.headers.get('retry-after'), null);
    assert.match(await res.text(), /Unsupported request model/);
    assert.equal(seen.length, 2, 'at most one sibling attempt');
    assert.ok(am.accounts.every(a => !a.pausedUntil && a.status === 'active'));
    assert.ok(am.accounts.every(a => a.inflight === 0), 'all object handles released');
  } finally {
    proxy.close();
    upstream.close();
  }
});

for (const cancel of [false, true]) {
  test(`headerless 429 backoff releases capacity and ${cancel ? 'cancels without reacquiring' : 'reacquires through the bounded queue'}`, { timeout: 8000 }, async t => {
    const am = new AccountManager([
      { name: 'a', type: 'oauth', accessToken: 't', expiresAt: Date.now() + 3600_000 },
    ], 0.98, { maxConcurrent: 1 });
    const controller = new AbortController();
    const healthyController = new AbortController();
    let hits = 0;
    let releaseHealthy;
    const healthyHeld = new Promise(resolve => { releaseHealthy = resolve; });
    const ended = [];
    const proxy = createProxyServer(am, {
      activeWarmup: false, upstream: 'http://upstream.invalid',
      overflowQueueTimeoutMs: null,
    }, {
      fetch: async () => {
        hits++;
        assert.equal(am.accounts[0].inFlight, 1, 'every dispatch owns exactly one slot');
        if (hits === 1) return new globalThis.Response('{"error":{"message":"retry"}}', { status: 429 });
        if (hits === 2) await healthyHeld;
        return new globalThis.Response('{"content":[]}', {
          headers: { 'content-type': 'application/json' },
        });
      },
      onRequestEnd: (_id, info) => ended.push(info.status),
    });
    const port = await listen(proxy);
    t.after(() => {
      controller.abort();
      healthyController.abort();
      releaseHealthy();
      proxy.closeAllConnections();
      proxy.close();
    });
    const waitFor = async (predicate, timeout = 1000) => {
      const deadline = Date.now() + timeout;
      while (!predicate() && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.ok(predicate(), 'expected observable request state before deadline');
    };
    const send = signal => fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-haiku-4', messages: [] }), signal,
    }).then(async response => {
      await response.text();
      return response.status;
    });
    // Handle rejection immediately: cancellation is an expected outcome.
    const retrying = send(controller.signal).catch(error => error);
    await waitFor(() => hits === 1 && am.accounts[0].inFlight === 0);
    const healthy = send(healthyController.signal).catch(error => error);
    await waitFor(() => hits === 2);
    assert.equal(am.accounts[0].inFlight, 1, 'another request uses capacity during backoff');
    if (cancel) {
      controller.abort();
      await waitFor(() => ended.includes(499));
      assert.ok(await retrying instanceof Error);
      await new Promise(resolve => setTimeout(resolve, 2100));
      assert.equal(hits, 2, 'cancelled backoff never dispatches its retry');
      assert.equal(am.accounts[0].inFlight, 1, 'cancellation does not release another request’s slot');
      releaseHealthy();
      assert.equal(await healthy, 200);
      await waitFor(() => am.accounts[0].inFlight === 0);
      assert.equal(am._waiters.length, 0);
    } else {
      await waitFor(() => am._waiters.length === 1, 3500);
      assert.equal(hits, 2, 'retry queues behind the healthy request instead of bypassing the cap');
      assert.equal(am.accounts[0].inFlight, 1);
      releaseHealthy();
      assert.equal(await healthy, 200);
      assert.equal(await retrying, 200, 'the previously tried account remains eligible for retry');
      assert.equal(hits, 3);
      assert.equal(am.accounts[0].inFlight, 0);
      assert.equal(am._waiters.length, 0);
    }
  });
}

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
    activeWarmup: false, proxy: { apiKey: 'k' },
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
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
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
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
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
    activeWarmup: false, proxy: { apiKey: 'k' },
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
    activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}`, holdMs: 3000,
  });
  const portLong = await listen(proxyLong);

  // Hold SHORTER than the throttle → give up when the hold runs out, not 30s later.
  const amShort = new AccountManager(acct(), 0.98);
  amShort.markRateLimited(0, 30);
  const proxyShort = createProxyServer(amShort, {
    activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}`, holdMs: 150,
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
// permanent synthetic 429. Recovery uses quota metadata, never a spending
// inference against a fleet that currently reads exhausted.
test('stale over-threshold quota recovers from metadata without a spending probe', async () => {
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
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const send = () => fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    const refused = await send();
    await refused.text();
    assert.equal(refused.status, 429);
    assert.equal(upstreamHits, 0, 'exhaustion must not authorize an inference probe');
    am.applyUsageData(0, { sevenDay: { utilization: 0.10, resetAt: Date.now() + 7 * 24 * 3600_000 } });
    const res = await send();
    await res.text();
    assert.equal(res.status, 200, 'fresh metadata must restore request eligibility');
    assert.equal(upstreamHits, 1, 'only the recovered client request spends inference');
    assert.equal(am.accounts[0].quota.unified7d, 0.10, 'fresh headroom remains recorded');
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
    activeWarmup: false, proxy: { apiKey: 'k' },
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
