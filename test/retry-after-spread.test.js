import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer, spreadRetryAfter } from '../src/server.js';

// Incident 2026-10-20: every account's 5-hour window was spent from 11:28 to
// 12:00 KST. Each refused session was told the same reset and slept to it to the
// second, so about forty of them sent their next request at 12:00:00 and resumed
// their tool calls together; the client Mac sat at a 1-minute load near 385 on
// 12 cores for about twenty minutes. The answer to one spent pool must not be the
// same second for every client it refuses.

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

test('a long wait is made later by at most a tenth of it, capped at three minutes', () => {
  assert.equal(spreadRetryAfter(600, () => 0), 600, 'the spread may add nothing');
  assert.equal(spreadRetryAfter(600, () => 0.999999), 660, 'a tenth of ten minutes is one minute');
  assert.equal(spreadRetryAfter(1800, () => 0.999999), 1980, 'thirty minutes spreads over the full three');
  assert.equal(spreadRetryAfter(3 * 86400, () => 0.999999), 3 * 86400 + 180, 'days stay capped at three minutes');
  for (const r of [0, 0.25, 0.5, 0.75, 0.999999]) {
    const s = spreadRetryAfter(1800, () => r);
    assert.ok(s >= 1800 && s <= 1980, `spread ${s} left [1800, 1980] for random ${r}`);
  }
});

test('a short wait stays exact', () => {
  // Throttles, cooldowns and the untimed 60s default: the number itself is what
  // the client needs, and a later one would only delay a slot that is free.
  for (const s of [1, 5, 30, 60, 300, 599]) {
    assert.equal(spreadRetryAfter(s, () => 0.999999), s, `${s}s was spread`);
  }
});

test('the wait is never made sooner', () => {
  // A client that wakes before the reset is refused again.
  for (const s of [600, 601, 1799, 7200]) {
    assert.ok(spreadRetryAfter(s, () => 0) >= s);
  }
});

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

test('one spent pool answers its refusals with different waits, none before the reset', async () => {
  let upstreamHits = 0;
  const upstream = http.createServer((req, res) => { upstreamHits++; res.writeHead(500); res.end(); });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager(['a', 'b'].map(name => ({
    name, type: 'oauth', accessToken: 'tok-' + name, refreshToken: 'r', expiresAt: Date.now() + HOUR,
  })), 0.98);
  const resetAt = Date.now() + 30 * MINUTE;
  for (const index of [0, 1]) {
    am.updateQuota(index, {
      'anthropic-ratelimit-unified-5h-utilization': '1',
      'anthropic-ratelimit-unified-5h-reset': String(Math.floor(resetAt / 1000)),
    });
  }
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    maxPredispatchWaitMs: 0,
    overflowQueueTimeoutMs: 0,
  });
  const port = await listen(proxy);

  try {
    // Each wait read as seconds past the reset, so the clock moving between
    // requests cannot pass for a spread.
    const late = [];
    for (let i = 0; i < 20; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: 'POST', body: '{"model":"claude-test"}',
      });
      const body = await res.json();
      assert.equal(res.status, 429, `request ${i} was not refused: ${JSON.stringify(body)}`);
      const pastReset = Number(res.headers.get('retry-after')) - (resetAt - Date.now()) / 1000;
      assert.ok(pastReset >= -2, `request ${i} was told to come back ${-pastReset}s before the reset`);
      assert.ok(pastReset <= 180 + 2, `request ${i} was told to come back ${pastReset}s after it`);
      late.push(pastReset);
    }
    // Unspread, every answer lands within a second or two of the reset; twenty
    // spread draws all under ten seconds is about 1 in 10^25.
    assert.ok(Math.max(...late) >= 10, `every refusal named the reset itself: ${late.map(Math.round)}`);
    assert.equal(upstreamHits, 0, 'a spent pool sent a request upstream');
  } finally {
    proxy.close();
    upstream.close();
  }
});
