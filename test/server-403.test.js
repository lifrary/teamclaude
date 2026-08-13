import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer, refusalCooldown, REFUSAL_BASE_SECONDS, REFUSAL_MAX_SECONDS } from '../src/server.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function oauth(name, token, extra = {}) {
  return { name, type: 'oauth', accessToken: token, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

function post(port) {
  return fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'x', messages: [] }),
  });
}

// Upstream answers 403 when it authenticated the credential but refuses to serve
// it — a lapsed subscription, an org that turned off Claude Code access, an edge
// block. Before this branch existed there was no handling at all: the 403 went
// straight back to the client and the account stayed 'active', so the next
// request picked the same account and failed identically. One lapsed account
// answered every request while the healthy ones sat idle.

test('a 403 fails over to a healthy account and never reaches the client', async () => {
  let aHits = 0;
  const upstream = http.createServer((req, res) => {
    if ((req.headers['authorization'] || '').includes('tok-a')) {
      aHits++;
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    }
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([oauth('a', 'tok-a'), oauth('b', 'tok-b')], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false, // isolate the failover from background warm-up probes
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await post(proxyPort);
    await res.text();
    assert.equal(res.status, 200, 'the client must get the healthy account, not the 403');
    assert.equal(aHits, 1);
    const a = am.accounts[0];
    assert.equal(a._403Strikes, 1);
    assert.equal(a.status, 'throttled', 'a refusal costs a cooldown');
    assert.notEqual(a.status, 'error', 'and never a park: recovery must not need a human re-login');
    assert.equal(a._403CooldownUntil, a.rateLimitedUntil, 'the deadline is tagged as refusal-derived');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// The actual bug: without a cooldown the refused account is neither throttled nor
// errored, so selection hands it right back and every request pays a 403.
test('the refused account is skipped by the next request', async () => {
  let aHits = 0;
  const upstream = http.createServer((req, res) => {
    if ((req.headers['authorization'] || '').includes('tok-a')) {
      aHits++;
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    }
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([oauth('a', 'tok-a'), oauth('b', 'tok-b')], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false,
  });
  const proxyPort = await listen(proxy);

  try {
    for (let i = 0; i < 3; i++) {
      const res = await post(proxyPort);
      await res.text();
      assert.equal(res.status, 200, `request ${i + 1} must be served`);
    }
    assert.equal(aHits, 1, `the refused account must be tried once, not once per request (got ${aHits})`);
  } finally {
    proxy.close();
    upstream.close();
  }
});

// With every account refused the client still must not see a 403: it never sees
// the credential we inject, so it cannot act on the refusal, and Claude Code
// reads a 403 as its OWN session dying and drops its login over it.
test('every account refused → a non-403 shortage naming the accounts', async () => {
  let hits = 0;
  const upstream = http.createServer((_req, res) => {
    hits++;
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([oauth('a', 'tok-a'), oauth('b', 'tok-b')], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false,
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await post(proxyPort);
    const body = await res.text();
    assert.notEqual(res.status, 403, 'a 403 here makes the client drop its own login');
    assert.ok(res.headers.get('retry-after'), 'the client needs a deadline to back off to');
    assert.match(body, /refused/i);
    assert.match(body, /"a"|a, b|\(a/, `the message must name the refused accounts, got: ${body}`);
    assert.ok(hits >= 1 && hits <= 4, `expected bounded retries, got ${hits}`);
    assert.ok(am.accounts.every(a => a.status !== 'error'), 'a refusal never parks an account');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// Escalation is what keeps a permanently dead account cheap: one wasted
// round-trip per cooldown window instead of one per request. It must escalate
// without ever reaching a park, because which upstream conditions mean "lapsed"
// is not knowable from here and every account leaves through one egress IP.
test('consecutive refusal rounds escalate the cooldown and still never park', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([oauth('a', 'tok-a')], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false,
  });
  const proxyPort = await listen(proxy);
  const a = am.accounts[0];

  try {
    // The deadline is armed from a clock read taken AFTER the round trip, so it
    // is never exactly `want` seconds past `before`. Assert a band rather than an
    // equality: rounding to the nearest second made this flake the moment a round
    // trip crossed 500ms, and the ladder's rungs are 60s apart — far outside any
    // slack a local round trip can consume.
    const want = [60, 120, 240];
    for (let round = 0; round < want.length; round++) {
      const before = Date.now();
      const res = await post(proxyPort);
      await res.text();
      const armedFor = (a.rateLimitedUntil - before) / 1000;
      assert.ok(armedFor >= want[round] && armedFor < want[round] + 30,
        `round ${round + 1}: expected a ~${want[round]}s cooldown, got ${armedFor.toFixed(1)}s`);
      // Retire the hold AND age the last-refusal stamp, both of which the clock
      // does for free once a cooldown elapses. The ageing is not cosmetic: three
      // rounds driven inside one millisecond are indistinguishable from a
      // concurrent burst, and the echo test correctly collapses them into one
      // round. In production consecutive rounds are a whole cooldown apart.
      am.clearRateLimited(a);
      a._403LastAt -= 1000;
    }
    assert.equal(a._403Strikes, 3);
    assert.notEqual(a.status, 'error', 'no number of refusals may cost a human re-login');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// An account can hold maxConcurrent requests at once, and one upstream blip
// answers 403 to all of them. That is one incident, not a run — counting each
// response would jump straight to the ceiling on a single blip.
test('concurrent refusals on one account count as a single round', async () => {
  const pending = [];
  const upstream = http.createServer((_req, res) => {
    pending.push(res);
    if (pending.length === 3) {
      for (const r of pending) {
        r.writeHead(403, { 'content-type': 'application/json' });
        r.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
      }
    }
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([oauth('a', 'tok-a', { maxConcurrent: 3 })], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false,
  });
  const proxyPort = await listen(proxy);

  try {
    const results = await Promise.all([post(proxyPort), post(proxyPort), post(proxyPort)]);
    await Promise.all(results.map(r => r.text()));
    assert.equal(pending.length, 3, 'all three must reach upstream before any response');
    assert.equal(am.accounts[0]._403Strikes, 1, 'three responses, one refusal round');
    assert.ok(results.every(r => r.status !== 403), 'no client sees the refusal');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// A concurrent request on the same account may have just taken a quota 429 with a
// far longer retry-after. Overwriting that with a 60s refusal cooldown would put
// the account back into rotation while upstream is still refusing it on quota,
// and would mislabel the quota hold as refusal-derived so a re-login would lift
// it. The revalidation-probe path is what lets a throttled account dispatch here.
test('a refusal neither clears nor shortens a longer hold already in place', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([oauth('a', 'tok-a')], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false,
  });
  const proxyPort = await listen(proxy);
  const a = am.accounts[0];

  try {
    am.markRateLimited(a, 3600);                                  // a real quota hold
    const quotaDeadline = a.rateLimitedUntil;
    a.throttledAt = Date.now() - am.throttleProbeFloorMs - 1;      // floor elapsed → probe allowed
    const res = await post(proxyPort);
    await res.text();

    assert.equal(a.rateLimitedUntil, quotaDeadline, 'the quota deadline must survive the 403 verbatim');
    assert.equal(a.status, 'throttled');
    assert.equal(a._403CooldownUntil, undefined, 'a hold we did not arm must not be tagged refusal-derived');
    assert.equal(a._403Strikes, 1, 'the refusal is still counted');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// Reachable only once the retry budget is spent while an account is still
// selectable: the no-account branch sleeps out a short hold and retries with a
// higher retryCount, and the account that wakes up then refuses.
test('a refusal with the retry budget spent answers 503, not 403', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([oauth('a', 'tok-a')], 0.98);   // maxRetries = 1
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false,
  });
  const proxyPort = await listen(proxy);

  try {
    am.markRateLimited(am.accounts[0], 0.2);   // expires during the no-account sleep
    const res = await post(proxyPort);
    const body = await res.text();
    assert.equal(res.status, 503);
    assert.equal(res.headers.get('retry-after'), '60');
    assert.match(body, /upstream_refused_error/);
    assert.match(body, /teamclaude login/);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('refusalCooldown: the ladder doubles to a ceiling and never shortens a longer hold', () => {
  const now = 1_000_000;
  assert.deepEqual([1, 2, 3, 4, 5, 9].map(n => refusalCooldown(n, null, now).seconds),
    [60, 120, 240, 300, 300, 300]);
  assert.equal(refusalCooldown(1, null, now).seconds, REFUSAL_BASE_SECONDS);
  assert.equal(refusalCooldown(99, null, now).seconds, REFUSAL_MAX_SECONDS);

  // No hold, or one expiring sooner than ours → arm.
  assert.equal(refusalCooldown(1, null, now).arm, true);
  assert.equal(refusalCooldown(1, now + 10_000, now).arm, true);
  // A hold outlasting ours (a quota 429's retry-after) → leave it alone.
  assert.equal(refusalCooldown(1, now + 3_600_000, now).arm, false);
  // Exactly equal is not longer: re-arming is a no-op, so allow it.
  assert.equal(refusalCooldown(1, now + 60_000, now).arm, true);
  // A strike count of 0 (state cleared under a late response) must not blow up
  // the exponent into a negative shift.
  assert.equal(refusalCooldown(0, null, now).seconds, REFUSAL_BASE_SECONDS);
});

test('replacing credentials clears the refusal run and lifts only the refusal cooldown', () => {
  const am = new AccountManager([oauth('a', 'tok-a'), oauth('b', 'tok-b')], 0.98);
  const [a, b] = am.accounts;

  // a: cooled down by a refusal. b: throttled by a real quota 429.
  am.markRateLimited(a, 300);
  a._403CooldownUntil = a.rateLimitedUntil;
  a._403Strikes = 4;
  a._403LastAt = Date.now();
  am.markRateLimited(b, 3600);
  const quotaDeadline = b.rateLimitedUntil;

  const fresh = { accessToken: 'new', refreshToken: 'r2', expiresAt: Date.now() + 3600_000 };
  am.updateAccountTokens(0, fresh);
  am.updateAccountTokens(1, fresh);

  assert.equal(a._403Strikes, undefined, 'the run describes credentials that no longer exist');
  assert.equal(a._403LastAt, undefined);
  assert.equal(a._403CooldownUntil, undefined);
  assert.equal(a.rateLimitedUntil, null, 'a refusal cooldown is void once the credentials change');
  assert.equal(a.status, 'active');

  assert.equal(b.rateLimitedUntil, quotaDeadline, 'a quota throttle is not a refusal and must survive');
  assert.equal(b.status, 'throttled');
});

test('a refusal cooldown is lifted even when the account was parked meanwhile', () => {
  const am = new AccountManager([oauth('a', 'tok-a')], 0.98);
  const a = am.accounts[0];
  am.markRateLimited(a, 300);
  a._403CooldownUntil = a.rateLimitedUntil;
  // Some other path parked it while the refusal hold was still armed. clearRateLimited
  // is guarded on status === 'throttled', so relying on it here would leave the stale
  // deadline behind and the account would stay benched past its heal.
  a.status = 'error';

  am.updateAccountTokens(0, { accessToken: 'new', refreshToken: 'r2', expiresAt: Date.now() + 3600_000 });

  assert.equal(a.status, 'active');
  assert.equal(a.rateLimitedUntil, null);
  assert.equal(a.throttledAt, null);
});

test('getStatus separates a refused account from a quota-throttled one', () => {
  const am = new AccountManager([oauth('a', 'tok-a'), oauth('b', 'tok-b')], 0.98);
  am.markRateLimited(am.accounts[0], 60);
  am.accounts[0]._403Strikes = 2;
  am.markRateLimited(am.accounts[1], 60);

  const [a, b] = am.getStatus().accounts;
  assert.equal(a.status, b.status, 'both read as throttled — status alone cannot tell them apart');
  assert.equal(a.refusals, 2, 'check the subscription');
  assert.equal(b.refusals, 0, 'wait for the reset');
});
