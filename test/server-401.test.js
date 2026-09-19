import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

const HOUR = 3600_000;

// An upstream that accepts only the tokens in `live` and 401s everything else —
// exactly how Anthropic answers an access token that was revoked before its
// clock expiry (something else refreshed the same token family). Records the
// bearer token presented on every hit so a test can prove WHICH credential was
// retried.
function revokingUpstream(live) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    seen.push(token);
    if (!live.has(token)) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'authentication_error', message: 'OAuth access token has been revoked' } }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  return { server, seen };
}

async function post(port) {
  const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'x', messages: [] }),
  });
  await res.text();
  return res.status;
}

// The core recovery: a token that upstream considers revoked is indistinguishable
// from a valid one by expiry alone, so only the 401 itself can trigger a refresh.
test('401 forces a token refresh and retries the same account', async () => {
  const { server: upstream, seen } = revokingUpstream(new Set(['fresh']));
  const upstreamPort = await listen(upstream);

  let refreshes = 0;
  const am = new AccountManager(
    // expiresAt is an hour out: the clock says this token is fine, upstream says otherwise.
    [{ name: 'a', type: 'oauth', accessToken: 'revoked', refreshToken: 'r', expiresAt: Date.now() + HOUR }],
    0.98,
    { refreshFn: async () => { refreshes++; return { accessToken: 'fresh', refreshToken: 'r2', expiresAt: Date.now() + HOUR }; } },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    assert.equal(await post(proxyPort), 200);          // client never sees the 401
    assert.equal(refreshes, 1);                        // forced despite a future expiresAt
    assert.deepEqual(seen, ['revoked', 'fresh']);      // retried with the NEW token
    assert.equal(am.accounts[0].status, 'active');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// When the refresh token is dead too (the whole family was revoked), there is
// nothing to recover on this account — it must drop out of rotation and the
// request must be served by another account rather than failing.
test('401 with a rejected refresh errors the account and fails over', async () => {
  const { server: upstream, seen } = revokingUpstream(new Set(['b-token']));
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(
    [
      { name: 'a', type: 'oauth', accessToken: 'revoked', refreshToken: 'dead', expiresAt: Date.now() + HOUR },
      { name: 'b', type: 'oauth', accessToken: 'b-token', refreshToken: 'r', expiresAt: Date.now() + HOUR },
    ],
    0.98,
    {
      refreshFn: async () => {
        const err = new Error('Token refresh failed (400): invalid_grant');
        err.status = 400;                              // a genuine auth rejection, not a blip
        throw err;
      },
    },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    assert.equal(await post(proxyPort), 200);          // served by the healthy account
    assert.deepEqual(seen, ['revoked', 'b-token']);
    assert.equal(am.accounts[0].status, 'error');      // dropped from rotation until re-login
    assert.equal(am.accounts[1].status, 'active');
  } finally {
    proxy.close();
    upstream.close();
  }
});

// Regression: the retry must be bounded. An upstream that 401s even a
// freshly-minted token must surface the 401, not loop refreshing forever.
test('persistent 401 terminates instead of looping', async () => {
  const { server: upstream, seen } = revokingUpstream(new Set());   // nothing is ever accepted
  const upstreamPort = await listen(upstream);

  let refreshes = 0;
  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + HOUR }],
    0.98,
    { refreshFn: async () => { refreshes++; return { accessToken: `t${refreshes}`, refreshToken: 'r', expiresAt: Date.now() + HOUR }; } },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    assert.equal(await post(proxyPort), 401);          // surfaced, not hung
    assert.equal(refreshes, 1);                        // one re-auth per account per request
    assert.equal(seen.length, 2);
  } finally {
    proxy.close();
    upstream.close();
  }
});

// An API-key account has no refresh token, so a 401 is a bad key — retrying it
// would just burn a round trip. It must pass straight through.
test('401 on an api-key account is not retried', async () => {
  const { server: upstream, seen } = revokingUpstream(new Set());
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([{ name: 'k', type: 'api_key', apiKey: 'sk-bad' }], 0.98);
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    assert.equal(await post(proxyPort), 401);
    assert.equal(seen.length, 1);                      // no retry
  } finally {
    proxy.close();
    upstream.close();
  }
});

// The refresh-storm guard. Every request already in flight when a token turns
// over comes back 401, staggered — so they miss the concurrent-refresh
// coalescing and would each force their own refresh, rotating the refresh-token
// family once per request. A 401 for a just-minted token is stale news; the
// forced refresh must be suppressed for a short window after a successful one.
test('a forced refresh is suppressed right after a successful refresh', async () => {
  let refreshes = 0;
  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't0', refreshToken: 'r', expiresAt: Date.now() + HOUR }],
    0.98,
    {
      forcedRefreshFloorMs: 10_000,
      refreshFn: async () => { refreshes++; return { accessToken: `t${refreshes}`, refreshToken: 'r', expiresAt: Date.now() + HOUR }; },
    },
  );

  await am.ensureTokenFresh(0, true);
  assert.equal(refreshes, 1);
  assert.equal(am.accounts[0].credential, 't1');

  // Two more stale 401s land immediately — neither may rotate the family again.
  await am.ensureTokenFresh(0, true);
  await am.ensureTokenFresh(0, true);
  assert.equal(refreshes, 1);
  assert.equal(am.accounts[0].credential, 't1');       // the good token survives
});

// The suppression must expire, or a token that really is bad stays stuck.
test('a forced refresh is allowed again once the floor elapses', async () => {
  let refreshes = 0;
  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't0', refreshToken: 'r', expiresAt: Date.now() + HOUR }],
    0.98,
    {
      forcedRefreshFloorMs: 30,
      refreshFn: async () => { refreshes++; return { accessToken: `t${refreshes}`, refreshToken: 'r', expiresAt: Date.now() + HOUR }; },
    },
  );

  await am.ensureTokenFresh(0, true);
  await am.ensureTokenFresh(0, true);
  assert.equal(refreshes, 1);                          // second one suppressed
  await new Promise(r => setTimeout(r, 50));
  await am.ensureTokenFresh(0, true);
  assert.equal(refreshes, 2);                          // floor elapsed, allowed
});

// End to end: a second request arriving inside the floor must not trigger a
// second rotation, even though it too gets a 401 (this upstream accepts
// nothing). Without the guard, refreshes would climb with every request.
test('back-to-back 401 requests rotate the token family once', async () => {
  const { server: upstream } = revokingUpstream(new Set());
  const upstreamPort = await listen(upstream);

  let refreshes = 0;
  const am = new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't0', refreshToken: 'r', expiresAt: Date.now() + HOUR }],
    0.98,
    {
      forcedRefreshFloorMs: 10_000,
      refreshFn: async () => { refreshes++; return { accessToken: `t${refreshes}`, refreshToken: 'r', expiresAt: Date.now() + HOUR }; },
    },
  );
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);

  try {
    assert.equal(await post(proxyPort), 401);
    assert.equal(await post(proxyPort), 401);
    assert.equal(refreshes, 1);                        // not once per request
  } finally {
    proxy.close();
    upstream.close();
  }
});

// Regression (adversarial review): a 401 (auth failure / revoked token) must
// fail the account out and switch — not get retried as a warm-up target,
// which would route repeated 401s to the client. Account 'a' has no refresh
// token, so the proxy can't refresh it: it must mark 'a' error and switch to
// the healthy account 'b' after a single 401.
test('a 401 marks the account error and switches, without repeated 401s', async () => {
  let aHits = 0;
  const upstream = http.createServer((req, res) => {
    const auth = req.headers['authorization'] || '';
    if (auth.includes('tok-a')) {
      aHits++;
      res.writeHead(401, { 'content-type': 'application/json' }); // no rate-limit headers
      res.end(JSON.stringify({ type: 'error', error: { type: 'authentication_error' } }));
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    }
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 'tok-a', expiresAt: Date.now() + 3600_000 }, // no refreshToken → can't refresh
    { name: 'b', type: 'oauth', accessToken: 'tok-b', refreshToken: 'r', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false, // isolate 401 failover from background warm-up probes
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 200);                  // switched to the healthy account
    assert.equal(aHits, 1, `revoked account must not be retried, got ${aHits} hits`);
    assert.equal(am.accounts[0].status, 'error');   // failed out → excluded from rotation + warm-up
  } finally {
    proxy.close();
    upstream.close();
  }
});

// When every account fails auth, the proxy surfaces a 401 to the client
// (bounded — no infinite retry).
test('all accounts failing auth → returns 401 to the client', async () => {
  let hits = 0;
  const upstream = http.createServer((_req, res) => {
    hits++;
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'authentication_error' } }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager([
    { name: 'a', type: 'oauth', accessToken: 'tok-a', expiresAt: Date.now() + 3600_000 },
    { name: 'b', type: 'oauth', accessToken: 'tok-b', expiresAt: Date.now() + 3600_000 },
  ], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false, // isolate 401 failover from background warm-up probes
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    await res.text();
    assert.equal(res.status, 401);
    assert.ok(hits >= 1 && hits <= 4, `expected bounded retries, got ${hits}`);
    assert.ok(am.accounts.every(a => a.status === 'error'));
  } finally {
    proxy.close();
    upstream.close();
  }
});
