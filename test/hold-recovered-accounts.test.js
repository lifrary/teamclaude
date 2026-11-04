import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

// A held request that failed over off every account used to sleep out its
// budget: forwardRequest recursed with the request's exclusions still naming
// each account that had already failed, so an account that recovered during the
// hold was never selected again (#603).
//
// The fork has one budgeted pre-dispatch hold (a configured `holdMs` bounded by
// maxPredispatchWaitMs) in place of upstream's inline waits, and it keeps no log
// line a mocked clock could follow, so these run on real timers with short
// holds. Every outcome below is decided by account state, not by a race: the
// timings only size each hold.

const SEC = 1000;
const HOUR = 3600 * SEC;

const listen = s => new Promise(r => s.listen(0, '127.0.0.1', () => r(s.address().port)));
const bearer = req => String(req.headers.authorization ?? '').replace(/^Bearer /, '');

const oauth = (name, token, expiresAt = Date.now() + HOUR) =>
  ({ name, type: 'oauth', accessToken: token, refreshToken: `r${token}`, expiresAt });

// A subscription 429 naming when its window resets, as upstream does: a quota
// rejection, so the account is held for `seconds` and selection skips it.
function rateLimited(res, seconds) {
  res.writeHead(429, {
    'content-type': 'application/json',
    'retry-after': String(seconds),
    'anthropic-ratelimit-unified-5h-status': 'rejected',
    'anthropic-ratelimit-unified-5h-reset': String(Math.floor((Date.now() + seconds * SEC) / 1000)),
    'anthropic-ratelimit-unified-5h-utilization': '1',
  });
  res.end('{"type":"error","error":{"type":"rate_limit_error"}}');
}

// A throttle that says nothing about quota: the account is paused and the
// request moves on, so it is excluded for this request only.
function throttled(res, seconds) {
  res.writeHead(429, { 'content-type': 'application/json', 'retry-after': String(seconds) });
  res.end('{"type":"error","error":{"type":"rate_limit_error"}}');
}

function overloaded(res) {
  res.writeHead(503, { 'content-type': 'application/json' });
  res.end('{"type":"error","error":{"type":"api_error"}}');
}

function served(res) {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end('{"ok":true}');
}

// Upstream refused the credential itself: a wait cannot fix this.
function refused(res) {
  res.writeHead(403, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error', message: 'Request not allowed' } }));
}

// respond(token, call, res) plays the upstream; `call` counts that token's
// requests from 1. Accounts are tried in array order while none is measured.
async function fleet(accounts, respond, { holdMs } = {}) {
  const seen = [];
  const times = [];
  const calls = new Map();
  const start = Date.now();
  const upstream = http.createServer((req, res) => {
    req.resume();
    const token = bearer(req);
    seen.push(token);
    times.push(Date.now() - start);
    calls.set(token, (calls.get(token) ?? 0) + 1);
    respond(token, calls.get(token), res);
  });
  const upPort = await listen(upstream);
  let refreshes = 0;
  const am = new AccountManager(accounts, 0.98, { refreshFn: async () => { refreshes++; throw new Error('no refresh in this test'); } });
  const proxy = createProxyServer(am, {
    activeWarmup: false, proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upPort}`,
    ...(holdMs ? { holdMs } : {}),
  });
  const port = await listen(proxy);
  return {
    port, seen, times, am, refreshes: () => refreshes,
    close() { proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); },
  };
}

// Resolves with the request's status, the retry-after it carried and how long it took.
function post(port) {
  const sent = Date.now();
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: '/v1/messages', method: 'POST',
      headers: { 'content-type': 'application/json' },
    }, res => {
      res.resume();
      res.once('end', () => resolve({ status: res.statusCode, retryAfter: res.headers['retry-after'], took: Date.now() - sent }));
    });
    req.once('error', reject);
    req.end(JSON.stringify({ model: 'x', messages: [] }));
  });
}

test('a held request retries an account that recovered after it failed over', async () => {
  // Both accounts are rate limited; a's window resets a second out, b's in a minute.
  const f = await fleet([oauth('a', 'ta'), oauth('b', 'tb')], (token, call, res) => {
    if (token === 'ta' && call > 1) return served(res);
    rateLimited(res, token === 'ta' ? 1 : 60);
  }, { holdMs: 3 * SEC });
  try {
    const r = await post(f.port);
    assert.equal(r.status, 200, `the held request was not served by the account that recovered (got ${r.status})`);
    assert.deepEqual(f.seen, ['ta', 'tb', 'ta'], 'two failed hops, then one retry on the recovered account');
    assert.ok(f.times[2] - f.times[1] >= 900, 'the retry waited for the hold, not sent at once');
  } finally { f.close(); }
});

// The failures a wait can cure are forgotten when the hold retries (the port of
// #603): a 5xx, and a throttle that paused the account. Without that, the
// account stays excluded for the rest of the request and the hold ends in 429.
test('a held request retries an account whose 5xx made it fail over', async () => {
  const f = await fleet([oauth('a', 'ta'), oauth('b', 'tb')], (token, call, res) => {
    if (token === 'ta') return call === 1 ? overloaded(res) : served(res);
    rateLimited(res, 60);
  }, { holdMs: 300 });
  try {
    const r = await post(f.port);
    assert.equal(r.status, 200, `the account that recovered from its 5xx was not retried after the hold (got ${r.status})`);
    assert.deepEqual(f.seen, ['ta', 'tb', 'ta']);
    assert.ok(f.times[2] - f.times[1] >= 250, 'the retry came after the hold');
  } finally { f.close(); }
});

test('a held request retries an account whose throttle paused it, once the pause lifts', async () => {
  const f = await fleet([oauth('a', 'ta'), oauth('b', 'tb')], (token, call, res) => {
    if (token === 'ta') return call === 1 ? throttled(res, 1) : served(res);
    rateLimited(res, 60);
  }, { holdMs: 1500 });
  try {
    const r = await post(f.port);
    assert.equal(r.status, 200, `the paused account was not retried once its pause lifted (got ${r.status})`);
    assert.deepEqual(f.seen, ['ta', 'tb', 'ta']);
    assert.ok(f.times[2] - f.times[1] >= 1000, 'the retry waited out the pause');
  } finally { f.close(); }
});

// b comes first in the rotation, so the request fails over onto a. The refused
// account stays excluded when the hold retries, as an unrenewable one does below.
test('a held request never retries an account upstream refused, even once another has recovered', async () => {
  const f = await fleet([oauth('b', 'tb'), oauth('a', 'ta')], (token, call, res) => {
    if (token === 'ta') return refused(res);
    if (call > 1) return served(res);
    rateLimited(res, 1);
  }, { holdMs: 3 * SEC });
  try {
    const r = await post(f.port);
    assert.equal(r.status, 200, `the held request was not served by the account that recovered (got ${r.status})`);
    assert.equal(f.seen.filter(x => x === 'ta').length, 1, 'the refused credential was sent again');
    assert.equal(f.seen.at(-1), 'tb', 'the retry goes to the account that recovered');
  } finally { f.close(); }
});

test('a held request never sends a token it could not renew, even once another has recovered', async () => {
  // a's token expired an hour ago and its refresh fails. b comes first in the
  // rotation, as in the refusal test above.
  const f = await fleet([oauth('b', 'tb'), oauth('a', 'ta', Date.now() - HOUR)], (token, call, res) => {
    if (call > 1) return served(res);
    rateLimited(res, 1);
  }, { holdMs: 3 * SEC });
  try {
    const r = await post(f.port);
    assert.equal(r.status, 200, `the held request was not served by the account that recovered (got ${r.status})`);
    assert.ok(!f.seen.includes('ta'), 'a token that could not be renewed was sent upstream');
    assert.equal(f.refreshes(), 1, 'the account whose token could not be renewed was selected again, and renewal retried');
  } finally { f.close(); }
});

// The retry after a hold is answered 429 again, although each account's own
// state said it had recovered. While the hold has time left its retry is a new
// attempt, so the request waits again and succeeds once upstream recovers,
// rather than returning that 429 with hold left.
test('a held request whose retry is still limited waits again and succeeds once upstream recovers', async () => {
  const opened = Date.now() + 1500;
  const f = await fleet([oauth('a', 'ta'), oauth('b', 'tb')], (token, call, res) => {
    if (Date.now() < opened) return rateLimited(res, 1);
    served(res);
  }, { holdMs: 4 * SEC });
  try {
    const r = await post(f.port);
    assert.equal(r.status, 200, `the held request returned ${r.status} with hold left, instead of waiting for upstream to recover`);
    // Attempts are paced by the hold: one failover chain reaches both accounts at
    // once, and the next chain only follows a wait.
    let chain = 1;
    for (let i = 1; i < f.times.length; i++) {
      const gap = f.times[i] - f.times[i - 1];
      if (gap < 250) chain++;
      else {
        assert.ok(gap >= 900, `attempts ${i - 1} and ${i} came ${gap}ms apart: a retry was sent without a wait (${f.seen.join(',')})`);
        chain = 1;
      }
      assert.ok(chain <= 2, `more than one failover chain without a wait (${f.seen.join(',')})`);
    }
  } finally { f.close(); }
});

// Upstream never recovers. The held request spends its hold and is answered
// with the 429 it always was: the hold, not the 30 s wait budget, ends it.
test('a held request whose hold budget runs out is answered 429', async () => {
  const f = await fleet([oauth('a', 'ta'), oauth('b', 'tb')], (_token, _call, res) => rateLimited(res, 1), { holdMs: 1200 });
  try {
    const r = await post(f.port);
    assert.equal(r.status, 429, `expected the hold to run out with a 429, got ${r.status}`);
    assert.ok(r.took >= 1100, `the hold was not spent (answered after ${r.took}ms)`);
    assert.ok(r.took < 5 * SEC, `the hold, not the wait budget, must end the wait (answered after ${r.took}ms)`);
    assert.ok(f.seen.length <= 8, `expected a bounded number of upstream calls, saw ${f.seen.length}`);
  } finally { f.close(); }
});

// No hold configured: upstream would wait inline for the soonest reset and retry.
test('an inline exhausted wait retries an account that recovered during it', async () => {
  const f = await fleet([oauth('a', 'ta'), oauth('b', 'tb')], (token, call, res) => {
    if (call > 1) return served(res);
    rateLimited(res, 5);
  });
  try {
    const r = await post(f.port);
    // Fork rule 3: no inline wait. A request that spent its hops on the fleet is
    // answered at once, with the soonest reset to come back at.
    assert.equal(r.status, 429);
    assert.deepEqual(f.seen, ['ta', 'tb'], 'nothing was retried without a configured hold');
    assert.ok(Number(r.retryAfter) >= 4 && Number(r.retryAfter) <= 5, `retry-after names the soonest reset, got ${r.retryAfter}`);
  } finally { f.close(); }
});
