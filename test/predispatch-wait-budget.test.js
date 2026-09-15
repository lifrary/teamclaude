import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

// When every account is throttled, the proxy sleeps until the soonest deadline and
// tries again. Each sleep is bounded; the SUM was not, and for its whole duration
// the client receives no status line at all. A caller cannot tell that from a dead
// network — Claude Code says "Waiting for API response ... check your network" —
// so an exhausted pool has to ANSWER, not go quiet.
async function requestAgainstFullyThrottledPool({ throttledForMs, maxPredispatchWaitMs }) {
  // Reached only if the proxy stops waiting and dispatches, which must not happen
  // here: every account is throttled for far longer than the budget.
  let upstreamHits = 0;
  const upstream = http.createServer((_req, res) => {
    upstreamHits++;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const upstreamPort = await listen(upstream);

  const accounts = ['a', 'b', 'c'].map(name => ({
    name, type: 'oauth', accessToken: 't', refreshToken: 'r',
    expiresAt: Date.now() + 3600_000,
  }));
  const am = new AccountManager(accounts, 0.98);
  // Use the manager's own setter: it also stamps throttledAt, which gates the
  // revalidation probe. Setting status/rateLimitedUntil by hand leaves that null
  // and the account is probed immediately, so the pool never reads as throttled.
  for (const account of am.accounts) am.markRateLimited(account, throttledForMs / 1000);

  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    maxPredispatchWaitMs,
  });
  const proxyPort = await listen(proxy);

  const startedAt = Date.now();
  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }),
    });
    const body = await res.json();
    return {
      status: res.status,
      retryAfter: res.headers.get('retry-after'),
      message: body?.error?.message ?? '',
      elapsedMs: Date.now() - startedAt,
      upstreamHits,
    };
  } finally {
    proxy.close();
    upstream.close();
  }
}

test('a fully throttled pool answers within the wait budget instead of going silent', async () => {
  // Throttled for 30s, budget 400ms. Without the budget the request sleeps the
  // full 30s and the client sees nothing at all in the meantime.
  const r = await requestAgainstFullyThrottledPool({
    throttledForMs: 30_000,
    maxPredispatchWaitMs: 400,
  });

  assert.equal(r.status, 429, 'an exhausted pool must answer, not hang');
  assert.ok(
    r.elapsedMs < 10_000,
    `must answer within the budget, took ${r.elapsedMs}ms (unbounded wait would be ~30s)`,
  );
  assert.ok(Number(r.retryAfter) > 0, `429 must carry a usable retry-after, got ${r.retryAfter}`);
  assert.match(r.message, /Retry in/, 'the body must tell the client when to come back');
  assert.equal(r.upstreamHits, 0, 'no account was available, so nothing may reach upstream');
});

test('a throttle shorter than the budget is still ridden out, not converted to a 429', async () => {
  // The budget must not turn a brief throttle into a client-visible failure.
  const r = await requestAgainstFullyThrottledPool({
    throttledForMs: 150,
    maxPredispatchWaitMs: 10_000,
  });

  assert.equal(r.status, 200, 'a throttle that clears inside the budget must still be waited out');
  assert.equal(r.upstreamHits, 1, 'the request must have been dispatched after the throttle lifted');
});

test('capacity wait survives the throttle deadline, runs FIFO, and cancels disconnected work', { timeout: 5000 }, async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push(req.headers['x-test-order']);
    res.end('{}');
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([{ name: 'a', type: 'api-key', apiKey: 'test' }], 0.98, 0, 1);
  const held = await am.acquireAccount(null, 0);
  assert.ok(held);
  const proxy = createProxyServer(am, {
    upstream: `http://127.0.0.1:${upstreamPort}`,
    overflowQueueTimeoutMs: null,
    maxPredispatchWaitMs: 20,
    activeWarmup: false,
  });
  const port = await listen(proxy);
  const controllers = [];
  const requests = [];
  const waitForDepth = async depth => {
    const deadline = Date.now() + 2000;
    while (am._waiters.length !== depth && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.equal(am._waiters.length, depth);
  };
  try {
    for (const order of ['first', 'cancelled', 'last']) {
      const controller = new AbortController();
      controllers.push(controller);
      requests.push(fetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: 'POST', body: '{}', signal: controller.signal,
        headers: { 'x-test-order': order },
      }).then(async res => { await res.text(); return res.status; }, () => 'aborted'));
      await waitForDepth(requests.length);
    }
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.equal(am._waiters.length, 3, 'capacity waits must survive the 20ms throttle budget');
    assert.deepEqual(seen, [], 'queued work must not bypass the account cap');
    controllers[1].abort();
    assert.equal(await requests[1], 'aborted');
    await waitForDepth(2);
    am.releaseAccount(held);
    assert.deepEqual(await Promise.all(requests), [200, 'aborted', 200]);
    assert.deepEqual(seen, ['first', 'last']);
    assert.equal(am._waiters.length, 0);
    assert.equal(am.accounts[0].inFlight, 0);
  } finally {
    for (const controller of controllers) controller.abort();
    am.releaseAccount(held);
    await Promise.all(requests);
    proxy.closeAllConnections();
    proxy.close();
    upstream.closeAllConnections();
    upstream.close();
  }
});
