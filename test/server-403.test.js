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
// it. Arm the quota hold after dispatch, just as a concurrent response can.
test('a refusal neither clears nor shortens a longer hold already in place', { timeout: 4000 }, async () => {
  let reached;
  const dispatched = new Promise(resolve => { reached = resolve; });
  const upstream = http.createServer((_req, res) => reached(res));
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
    const response = post(proxyPort);
    const held = await dispatched;
    const originalRefusalDeadline = a._403CooldownUntil;
    assert.equal(originalRefusalDeadline, null, 'no refusal-derived hold existed before dispatch');
    am.markRateLimited(a, 3600);                                  // a real quota hold
    const quotaDeadline = a.rateLimitedUntil;
    held.writeHead(403, { 'content-type': 'application/json' });
    held.end(JSON.stringify({ type: 'error', error: { type: 'permission_error' } }));
    const res = await response;
    await res.text();

    assert.notEqual(res.status, 403, 'the injected credential refusal must not reach the client');
    assert.equal(a.rateLimitedUntil, quotaDeadline, 'the quota deadline must survive the 403 verbatim');
    assert.equal(a.status, 'throttled');
    assert.equal(a._403CooldownUntil, originalRefusalDeadline, 'a hold we did not arm must not be tagged refusal-derived');
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

const HOUR = 3600_000;

// Upstream answers 403 "Request not allowed" to every token outside `live` —
// how Anthropic rejects a credential it will not serve at all (as opposed to a
// 401, which says the token merely needs refreshing). Records each bearer so a
// test can prove which account was tried.
function forbiddingUpstream(live) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    seen.push(token);
    if (!live.has(token)) {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error', message: 'Request not allowed' } }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  return { server, seen };
}

async function postUpstream(port, path = '/v1/messages') {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'x', messages: [] }),
  });
  return { status: res.status, body: await res.text(), headers: res.headers };
}

function entitlementError(code = 'oauth_not_allowed_for_organization') {
  return {
    type: 'error',
    error: {
      type: 'permission_error',
      message: 'OAuth authentication is currently not allowed for this organization.',
      details: { error_code: code },
    },
    request_id: 'req_test',
  };
}

function entitlementUpstream({ deniedToken = 'a-token', delayMs = 0 } = {}) {
  const seen = [];
  const server = http.createServer(async (req, res) => {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    seen.push(token);
    if (token === deniedToken) {
      if (delayMs) await new Promise(resolve => setTimeout(resolve, delayMs));
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify(entitlementError()));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  return { server, seen };
}

function twoAccounts() {
  return [
    { name: 'a account', type: 'oauth', accessToken: 'a-token', refreshToken: 'ra', expiresAt: Date.now() + HOUR },
    { name: 'b account', type: 'oauth', accessToken: 'b-token', refreshToken: 'rb', expiresAt: Date.now() + HOUR },
  ];
}

// The client never sees the credential the proxy injects, so a 403 about that
// credential is not something the client can act on — but Claude Code reads a
// 403 as "your session is dead", drops its own login and asks for a re-login.
// Retain the local retryable shortage: the refused account cools down rather
// than being permanently parked, and the client's own credential is untouched.
test('a 403 on the injected credential reaches the client as a shortage, not a 403', async () => {
  const { server: upstream, seen } = forbiddingUpstream(new Set());   // nothing is accepted
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + HOUR }],
    0.98,
    { refreshFn: async () => { throw new Error('must not refresh on a 403'); } },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    const { status, body } = await postUpstream(proxyPort);
    assert.equal(status, 429);
    assert.match(body, /rate_limit_error/);
    assert.match(JSON.parse(body).error.message, /\(a\)/);
    assert.match(body, /refused/);
    assert.equal(seen.length, 1);                      // no other account to try
  } finally {
    proxy.close();
    upstream.close();
  }
});

// A 403 is about one account's credential, so the request itself is still
// serveable — fail over the way the 401 path does rather than giving up.
test('a 403 fails over to another account', async () => {
  const { server: upstream, seen } = forbiddingUpstream(new Set(['b-token']));
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [
      { name: 'a', type: 'oauth', accessToken: 'a-token', refreshToken: 'ra', expiresAt: Date.now() + HOUR },
      { name: 'b', type: 'oauth', accessToken: 'b-token', refreshToken: 'rb', expiresAt: Date.now() + HOUR },
    ],
    0.98,
    { refreshFn: async () => { throw new Error('must not refresh on a 403'); } },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    const { status } = await postUpstream(proxyPort);
    assert.equal(status, 200);
    assert.deepEqual(seen, ['a-token', 'b-token']);
  } finally {
    proxy.close();
    upstream.close();
  }
});

// Two refused credentials: name both while retaining the local cooldown.
test('with every account refused the error names all of them', async () => {
  const { server: upstream } = forbiddingUpstream(new Set());
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [
      { name: 'a', type: 'oauth', accessToken: 'ta', refreshToken: 'ra', expiresAt: Date.now() + HOUR },
      { name: 'b', type: 'oauth', accessToken: 'tb', refreshToken: 'rb', expiresAt: Date.now() + HOUR },
    ],
    0.98,
    { refreshFn: async () => { throw new Error('must not refresh on a 403'); } },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    const { status, body } = await postUpstream(proxyPort);
    assert.equal(status, 429);
    assert.match(JSON.parse(body).error.message, /\(a, b\)/);
  } finally {
    proxy.close();
    upstream.close();
  }
});

// The mixed fleet: one credential is refused, the other account is merely out of
// quota. A reset will still serve this request, so the refusal must not short —
// circuit the exhaustion path — otherwise one bad credential turns every
// recoverable exhaustion into a hard 502 and skips the holdSeconds wait that an
// unattended run depends on.
test('a refusal alongside a merely-exhausted account still reports exhaustion', async () => {
  const upstream = http.createServer((req, res) => {
    if (req.headers.authorization === 'Bearer ta') {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error', message: 'Request not allowed' } }));
      return;
    }
    // Durable quota rejection, far enough out that no inline retry absorbs it.
    res.writeHead(429, {
      'retry-after': '300',
      'anthropic-ratelimit-unified-5h-status': 'rejected',
      'content-type': 'application/json',
    });
    res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [
      { name: 'a', type: 'oauth', accessToken: 'ta', refreshToken: 'ra', expiresAt: Date.now() + HOUR },
      { name: 'b', type: 'oauth', accessToken: 'tb', refreshToken: 'rb', expiresAt: Date.now() + HOUR },
    ],
    0.98,
    { refreshFn: async () => { throw new Error('must not refresh on a 403'); } },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    const { status, body } = await postUpstream(proxyPort);
    assert.equal(status, 429, 'quota exhaustion, not a hard credential error');
    assert.match(body, /rate_limit_error/);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('an OAuth entitlement denial quarantines the account across requests', async () => {
  const { server: upstream, seen } = entitlementUpstream();
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(twoAccounts(), 0.98);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const first = await postUpstream(proxyPort);
    assert.equal(first.status, 200);
    assert.deepEqual(seen, ['a-token', 'b-token']);
    assert.ok(am.accounts[0].entitlementDeniedUntil > Date.now());

    am.currentIndex = 0;
    const second = await postUpstream(proxyPort);
    assert.equal(second.status, 200);
    assert.deepEqual(seen, ['a-token', 'b-token', 'b-token']);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('a generic 403 gets only the local refusal cooldown, not entitlement quarantine', async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    seen.push(token);
    if (token === 'a-token') {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify(entitlementError('different_permission_error')));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(twoAccounts(), 0.98);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    assert.equal((await postUpstream(proxyPort)).status, 200);
    assert.equal(am.accounts[0].entitlementDeniedUntil, null);
    am.currentIndex = 0;
    assert.equal((await postUpstream(proxyPort)).status, 200);
    assert.deepEqual(seen, ['a-token', 'b-token', 'b-token']);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('an account is selected again after its entitlement cooldown expires', async () => {
  const { server: upstream, seen } = entitlementUpstream();
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(twoAccounts(), 0.98);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    assert.equal((await postUpstream(proxyPort)).status, 200);
    am.accounts[0].entitlementDeniedUntil = Date.now() - 1;
    am.currentIndex = 0;
    assert.equal((await postUpstream(proxyPort)).status, 200);
    assert.deepEqual(seen, ['a-token', 'b-token', 'a-token', 'b-token']);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('requests queued on an account rotate if another request quarantines it', async () => {
  const { server: upstream, seen } = entitlementUpstream({ delayMs: 30 });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(twoAccounts(), 0.98, {
    ramp: { enabled: true, startConc: 1, stepConc: 1, stepMs: 1000, windowMs: 30_000, pollMs: 5 },
  });
  am.accounts[0].rampStartedAt = Date.now();
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const [first, second] = await Promise.all([postUpstream(proxyPort), postUpstream(proxyPort)]);
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(seen.filter(token => token === 'a-token').length, 1);
    assert.equal(seen.filter(token => token === 'b-token').length, 2);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('a fully cooling fleet reports the entitlement re-admission time', async () => {
  const { server: upstream, seen } = entitlementUpstream({ deniedToken: 'only-token' });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([
    { name: 'only', type: 'oauth', accessToken: 'only-token', refreshToken: 'r', expiresAt: Date.now() + HOUR },
  ]);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    assert.equal((await postUpstream(proxyPort)).status, 502);
    const result = await postUpstream(proxyPort);
    assert.equal(result.status, 429);
    const retryAfter = Number(result.headers.get('retry-after'));
    assert.ok(retryAfter > 60);
    assert.ok(retryAfter <= 300);
    assert.deepEqual(seen, ['only-token']);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('an all-entitlement-denied 502 diagnoses policy instead of recommending login', async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push((req.headers.authorization || '').replace(/^Bearer /, ''));
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify(entitlementError()));
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(twoAccounts(), 0.98);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const result = await postUpstream(proxyPort);
    assert.equal(result.status, 502);
    const message = JSON.parse(result.body).error.message;
    assert.match(message, /No account served this request/);
    assert.match(message, /Every configured account returned OAuth entitlement denial/);
    assert.match(message, /oauth_not_allowed_for_organization/);
    assert.match(message, /"a account"/);
    assert.match(message, /"b account"/);
    assert.doesNotMatch(message, /teamclaude login/);
    assert.deepEqual(seen, ['a-token', 'b-token']);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('a non-JSON 403 does not quarantine the account', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('oauth_not_allowed_for_organization');
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([
    { name: 'only', type: 'oauth', accessToken: 'token', refreshToken: 'r', expiresAt: Date.now() + HOUR },
  ]);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    assert.equal((await postUpstream(proxyPort)).status, 429);
    assert.equal(am.accounts[0].entitlementDeniedUntil, null);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('an oversized 403 body is not buffered or used to quarantine', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ...entitlementError(), padding: 'x'.repeat(70 * 1024) }));
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([
    { name: 'only', type: 'oauth', accessToken: 'token', refreshToken: 'r', expiresAt: Date.now() + HOUR },
  ]);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    assert.equal((await postUpstream(proxyPort)).status, 429);
    assert.equal(am.accounts[0].entitlementDeniedUntil, null);
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('a caller-pinned request goes to exactly the account it targeted', async () => {
  const { server: upstream, seen } = entitlementUpstream();
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(twoAccounts(), 0.98);
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const result = await postUpstream(proxyPort, '/tc-acct/b%20account/v1/messages');
    assert.equal(result.status, 200);
    assert.deepEqual(seen, ['b-token']);
  } finally {
    proxy.close();
    upstream.close();
  }
});
