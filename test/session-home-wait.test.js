import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

// A distributed session's prompt cache lives on the account it is pinned to.
// These tests pin down when a request stays there and when it may leave.

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

const OPUS = 'claude-opus-5-5';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function fleet(opts = {}, accounts = [oauth('a'), oauth('b')]) {
  return new AccountManager(accounts, 0.98, {
    distributeSessions: true, maxConcurrent: 1, queueTimeoutMs: null, ...opts,
  });
}

/** Hold one slot on `account` the way a request would, and hand back the release. */
function occupy(am, account) {
  account.inFlight++;
  return () => am.releaseAccount(account);
}

function ctx(sessionId) {
  return { sessionId, model: OPUS };
}

/** Acquire, and fail if it took anywhere near the configured home wait. */
async function prompt(am, exclude, context) {
  const started = Date.now();
  const account = await am.acquireAccount(exclude, null, null, null, context);
  assert.ok(Date.now() - started < 1_000, 'served at once, not after waiting for the home');
  return account;
}

test('a request whose session home is at its cap waits for the home instead of spilling', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  const free = occupy(am, a);

  const pending = am.acquireAccount(null, null, null, null, ctx('s1'));
  await sleep(30);
  assert.equal(b.inFlight, 0, 'the request must not be sent to an account without its cache');

  free();
  assert.equal(await pending, a, 'the freed home slot goes to its own session');
  assert.equal(am.sessionTracker.pinnedAccount('s1', am._weeklyBucketFor(OPUS)), a.index);
});

test('once the home wait runs out the request is served wherever there is room', async () => {
  const am = fleet({ sessionHomeWaitMs: 40 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  const started = Date.now();
  const account = await am.acquireAccount(null, null, null, null, ctx('s1'));
  assert.equal(account, b);
  assert.ok(Date.now() - started >= 35, 'it waited for the home first');
});

test('waiting for the home never turns into a refusal when the queue cannot take the request', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000, maxQueueDepth: 0 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  assert.equal(await am.acquireAccount(null, null, null, null, ctx('s1')), b);
});

test('a request that cannot wait at all is served elsewhere rather than refused', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  assert.equal(await am.acquireAccount(null, 0, null, null, ctx('s1')), b);
});

test('the home wait is at most half a finite queue timeout, so the request is still served in time', async () => {
  const am = fleet({ sessionHomeWaitMs: 60_000 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  const started = Date.now();
  assert.equal(await am.acquireAccount(null, 400, null, null, ctx('s1')), b);
  assert.ok(Date.now() - started < 350, 'served once half the timeout passed, not at the timeout itself');
});

test('an account the request already failed on is not waited for', async () => {
  // A third account at its cap keeps the request queueable, so only the home
  // check itself can stop it waiting for the account it just failed on.
  const am = fleet({ sessionHomeWaitMs: 5_000 }, [oauth('a'), oauth('b'), oauth('c')]);
  const [a, b, c] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);
  occupy(am, b);

  assert.equal(await prompt(am, new Set([a]), ctx('s1')), c);
});

test('a home that cannot serve is not waited for', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);
  a.status = 'exhausted';

  assert.equal(await prompt(am, null, ctx('s1')), b);
});

test('when the family pin cannot serve, the session waits for the account it holds for another family', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 }, [oauth('a'), oauth('b'), oauth('c')]);
  const [a, b, c] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  am.recordSession('s1', b.index, 'claude-fable-5');
  a.status = 'exhausted';
  const freeB = occupy(am, b);

  const pending = am.acquireAccount(null, null, null, null, ctx('s1'));
  await sleep(30);
  assert.equal(c.inFlight, 0, 'the session already has a cache on b, so it waits there');
  freeB();
  assert.equal(await pending, b);
});

test('a new session has no home and is placed without waiting', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 });
  const [a, b] = am.accounts;
  occupy(am, a);

  assert.equal(await prompt(am, null, ctx('fresh')), b);
});

test('home waiting is off unless configured, which keeps the old immediate spill', async () => {
  const am = fleet();
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  assert.equal(await am.acquireAccount(null, null, null, null, ctx('s1')), b);
});

test('a freed slot goes to the waiter whose home it is, ahead of an older waiter from elsewhere', async () => {
  // The older waiter is still inside its home wait, so it declines the other
  // session's home and the slot passes to the session that lives there.
  const am = fleet({ sessionHomeWaitMs: 5_000 });
  const [a, b] = am.accounts;
  am.recordSession('on-a', a.index, OPUS);
  am.recordSession('on-b', b.index, OPUS);
  const freeA = occupy(am, a);
  const freeB = occupy(am, b);

  let older = null;
  let younger = null;
  am.acquireAccount(null, null, null, null, ctx('on-b')).then(account => { older = account; });
  await sleep(5);
  am.acquireAccount(null, null, null, null, ctx('on-a')).then(account => { younger = account; });
  await sleep(5);

  freeA();
  await sleep(5);
  assert.equal(younger, a, 'the slot on a goes to the session that lives on a');
  assert.equal(older, null, 'the older waiter keeps waiting for its own home');

  freeB();
  await sleep(5);
  assert.equal(older, b);
});

test('a waiter with no home is served in arrival order, not behind home waiters', async () => {
  const am = fleet({ sessionHomeWaitMs: 30_000 });
  const [a, b] = am.accounts;
  am.recordSession('on-a', a.index, OPUS);
  const freeA = occupy(am, a);
  occupy(am, b);

  let fresh = null;
  am.acquireAccount(null, null, null, null, ctx('fresh')).then(account => { fresh = account; });
  await sleep(5);
  const homeWaiter = am.acquireAccount(null, null, null, null, ctx('on-a'));
  await sleep(5);

  freeA();
  await sleep(5);
  assert.equal(fresh, a, 'the older, homeless waiter takes the slot a home waiter would also want');
  am.releaseAccount(a);
  assert.equal(await homeWaiter, a, 'and the home waiter gets its home next');
});

test('with home waiting off the queue is plain arrival order', async () => {
  const am = fleet({ sessionHomeWaitMs: 0 });
  const [a, b] = am.accounts;
  am.recordSession('on-a', a.index, OPUS);
  am.recordSession('on-b', b.index, OPUS);
  const freeA = occupy(am, a);
  occupy(am, b);

  let older = null;
  am.acquireAccount(null, null, null, null, ctx('on-b')).then(account => { older = account; });
  await sleep(5);
  const younger = am.acquireAccount(null, null, null, null, ctx('on-a'));
  await sleep(5);

  freeA();
  await sleep(5);
  assert.equal(older, a);
  am.releaseAccount(b);
  assert.equal(await younger, b);
});

test('a home paused for longer than the wait could last is not waited for', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000, maxConcurrent: 3 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  am.pauseAccount(a.index, 60);

  assert.equal(await prompt(am, null, ctx('s1')), b);
});

test('a short pause on the home is waited out', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000, maxConcurrent: 3 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  a.pausedUntil = Date.now() + 60;

  assert.equal(await am.acquireAccount(null, null, null, null, ctx('s1')), a);
  assert.equal(b.inFlight, 0);
});

test('a timeout shorter than the drain poll still serves the request elsewhere', async () => {
  for (const timeout of [40, 45]) {
    const am = fleet({ sessionHomeWaitMs: 30_000 });
    const [a, b] = am.accounts;
    am.recordSession('s1', a.index, OPUS);
    occupy(am, a);

    assert.equal(await am.acquireAccount(null, timeout, null, null, ctx('s1')), b, `timeout ${timeout} ms`);
  }
});

test('a queued advisor request whose advisor becomes unservable is not refused while an account is free', async () => {
  const am = fleet({ sessionHomeWaitMs: 30_000, routes: [{ name: 'adv', match: ['claude-haiku-*'], accounts: ['a'] }] },
    [oauth('a'), oauth('b'), oauth('c')]);
  const [a] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  let result;
  am.acquireAccount(null, null, null, null, { ...ctx('s1'), advisorModel: 'claude-haiku-9' }).then(account => { result = account; });
  await sleep(20);
  am.setRoutes([{ name: 'adv', match: ['claude-haiku-*'], accounts: ['nobody'] }]);
  await sleep(150);
  assert.ok(result && result !== a, `served elsewhere, got ${result === null ? 'a refusal' : result?.name}`);
});

test('an unranked pin at its cap is waited for when the ranked account is busy too', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 }, [oauth('R', { priority: 0 }), oauth('U1'), oauth('U2')]);
  const [R, U1, U2] = am.accounts;
  am.recordSession('s1', U1.index, OPUS);
  occupy(am, R);
  const freeU1 = occupy(am, U1);

  const pending = am.acquireAccount(null, null, null, null, ctx('s1'));
  await sleep(30);
  assert.equal(U2.inFlight, 0, 'selection keeps U1, so the request waits for it');
  freeU1();
  assert.equal(await pending, U1);
});

test('a session pinned to a metered account ranked last goes back to a better-ranked subscription', () => {
  const am = new AccountManager([
    oauth('first', { priority: 0 }),
    { name: 'reserve', type: 'apikey', apiKey: 'k-reserve', priority: 9 },
  ], 0.98, { distributeSessions: true });
  am.recordSession('s1', 1, OPUS);

  assert.equal(am.getActiveAccount(null, OPUS, null, 's1').name, 'first',
    'staying on a metered reserve has a price, so the pin still yields');
});

test('a waiter with no home still takes a freed slot in arrival order', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 });
  const [a] = am.accounts;
  const freeA = occupy(am, a);
  occupy(am, am.accounts[1]);

  const pending = am.acquireAccount(null, null, null, null, ctx('fresh'));
  await sleep(5);
  freeA();
  assert.equal(await pending, a);
});

test('a ranked sibling with a free slot does not pull a pinned session off its account', () => {
  const am = new AccountManager([
    oauth('second', { priority: 1 }),
    oauth('first', { priority: 0 }),
  ], 0.98, { distributeSessions: true });
  am.recordSession('s1', 0, OPUS);

  assert.equal(am.getActiveAccount(null, OPUS, null, 's1').name, 'second',
    'priority places new sessions; it does not move a session that has a usable home');
  assert.equal(am.getActiveAccount(null, OPUS, null, 'new').name, 'first',
    'a new session still goes to the preferred account');
});

test('pin moves are counted in the status readout', () => {
  const am = fleet({ sessionHomeWaitMs: 30_000 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  am.recordSession('s1', a.index, OPUS);
  am.recordSession('s1', b.index, OPUS);

  const { sessions } = am.getStatus();
  assert.equal(sessions.moved, 1, 'placing a session is not a move; changing its account is');
  assert.equal(sessions.homeWaitMs, 30_000);
});

test('a request that opts out of home waiting is served at once', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 });
  const [a, b] = am.accounts;
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  assert.equal(await prompt(am, null, { ...ctx('s1'), homeWaitUntil: null }), b);
});

// Server wiring: only a completion has a cache worth waiting for or pinning.

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

async function withProxy(am, fn) {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"input_tokens":1}');
  });
  const upstreamPort = await listen(upstream);
  const proxy = createProxyServer(am, { proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` }, {});
  const port = await listen(proxy);
  try {
    await fn(port);
  } finally {
    proxy.close();
    upstream.close();
  }
}

function post(port, path, sessionId) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path,
      headers: { 'content-type': 'application/json', 'x-api-key': 'k', 'x-claude-code-session-id': sessionId },
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject);
    req.end(JSON.stringify({ model: OPUS, messages: [] }));
  });
}

function keyed(name) {
  return { name, type: 'apikey', apiKey: 'k-' + name };
}

test('a count_tokens call neither waits for the session home nor moves its pin', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 }, [keyed('a'), keyed('b')]);
  const [a, b] = am.accounts;
  const bucket = am._weeklyBucketFor(OPUS);
  am.recordSession('s1', a.index, OPUS);
  occupy(am, a);

  await withProxy(am, async (port) => {
    const started = Date.now();
    assert.equal(await post(port, '/v1/messages/count_tokens', 's1'), 200);
    assert.ok(Date.now() - started < 1_000, 'served on b at once rather than after the home wait');
    assert.equal(b.inFlight, 0);
    assert.equal(am.sessionTracker.pinnedAccount('s1', bucket), a.index, 'the pin stays with the cache');
  });
});

test('a completion pins its session and a count_tokens call does not', async () => {
  const am = fleet({ sessionHomeWaitMs: 5_000 }, [keyed('a'), keyed('b')]);
  const bucket = am._weeklyBucketFor(OPUS);

  await withProxy(am, async (port) => {
    assert.equal(await post(port, '/v1/messages/count_tokens', 'counted'), 200);
    assert.equal(am.sessionTracker.pinnedAccount('counted', bucket), null);
    assert.equal(await post(port, '/v1/messages', 'completed'), 200);
    assert.notEqual(am.sessionTracker.pinnedAccount('completed', bucket), null);
  });
});
