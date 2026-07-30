import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUsageBucket, findScopedWeeklyLimit } from '../src/oauth.js';
import { AccountManager, isFableModel, parseRequestModel } from '../src/account-manager.js';
import { Prober } from '../src/prober.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, expiresAt: Date.now() + 3600_000, ...extra };
}

// ── normalizeUsageBucket ──────────────────────────────────────

test('normalizeUsageBucket converts OAuth usage percentages to 0-1', () => {
  assert.equal(normalizeUsageBucket({ used_percentage: 42 }).utilization, 0.42);
  assert.equal(normalizeUsageBucket({ utilization: 1 }).utilization, 0.01);
  assert.equal(normalizeUsageBucket({ utilization: 2 }).utilization, 0.02);
  assert.equal(normalizeUsageBucket({ utilization: 100 }).utilization, 1);
  assert.equal(normalizeUsageBucket({ used_percentage: '30' }).utilization, 0.3);
  assert.equal(normalizeUsageBucket({ used_percentage: 1 }).utilization, 0.01);
  assert.equal(normalizeUsageBucket({ used_percentage: '1' }).utilization, 0.01);
  assert.equal(normalizeUsageBucket({ usedPercentage: '1' }).utilization, 0.01);
  assert.equal(normalizeUsageBucket({ utilization: '1' }).utilization, 0.01);
  assert.equal(normalizeUsageBucket(null), null);
  assert.equal(normalizeUsageBucket({}).utilization, null);
});

test('normalizeUsageBucket normalizes resets to ms epoch', () => {
  assert.equal(normalizeUsageBucket({ resets_at: 1700000000 }).resetAt, 1700000000000);     // seconds → ms
  assert.equal(normalizeUsageBucket({ resets_at: 1700000000000 }).resetAt, 1700000000000);  // already ms
  assert.equal(normalizeUsageBucket({ resets_at: '2026-01-01T00:00:00Z' }).resetAt, Date.parse('2026-01-01T00:00:00Z'));
});

// ── findScopedWeeklyLimit ─────────────────────────────────────

test('findScopedWeeklyLimit pulls a per-model weekly bucket from limits[]', () => {
  // Shape mirrors the real /api/oauth/usage payload: model-scoped weekly quota
  // lives in limits[] (the legacy seven_day_<model> top-level keys read null).
  const data = { limits: [
    { kind: 'session', group: 'session', percent: 47, scope: null },
    { kind: 'weekly_all', group: 'weekly', percent: 8, scope: null },
    { kind: 'weekly_scoped', group: 'weekly', percent: 100,
      resets_at: '2026-07-03T17:00:00Z', scope: { model: { display_name: 'Fable' } } },
  ]};
  const b = normalizeUsageBucket(findScopedWeeklyLimit(data, /fable/i));
  assert.equal(b.utilization, 1);
  assert.equal(b.resetAt, Date.parse('2026-07-03T17:00:00Z'));

  assert.equal(findScopedWeeklyLimit(data, /sonnet/i), null);   // no Sonnet-scoped entry
  assert.equal(findScopedWeeklyLimit({}, /fable/i), null);      // no limits[] at all
  assert.equal(findScopedWeeklyLimit({ limits: [] }, /fable/i), null);
});

// ── applyUsageData ────────────────────────────────────────────

test('applyUsageData populates 5h/7d/sonnet/fable without counting a request', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.applyUsageData(0, {
    fiveHour: { utilization: 0.2, resetAt: 111 },
    sevenDay: { utilization: 0.4, resetAt: 222 },
    sevenDaySonnet: { utilization: 0.6, resetAt: 333 },
    sevenDayFable: { utilization: 0.5, resetAt: 444 },
  });
  const a = am.accounts[0];
  assert.equal(a.quota.unified5h, 0.2);
  assert.equal(a.quota.unified7d, 0.4);
  assert.equal(a.quota.unified7dSonnet, 0.6);
  assert.equal(a.quota.unified7dSonnetReset, 333);
  assert.equal(a.quota.unified7dFable, 0.5);
  assert.equal(a.quota.unified7dFableReset, 444);
  assert.equal(a.usage.totalRequests, 0);   // a probe is not real traffic
  assert.equal(a.probing, false);            // learned the weekly window…
  assert.equal(a.requalify, true);           // …so re-evaluate selection
});

test('sonnet + fable quota survive the persistence round-trip', () => {
  const am1 = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am1.applyUsageData(0, {
    sevenDaySonnet: { utilization: 0.7, resetAt: 999 },
    sevenDayFable: { utilization: 0.3, resetAt: 888 },
  });
  const am2 = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am2.restoreCanonicalState(am1.exportCanonicalState());
  assert.equal(am2.accounts[0].quota.unified7dSonnet, 0.7);
  assert.equal(am2.accounts[0].quota.unified7dSonnetReset, 999);
  assert.equal(am2.accounts[0].quota.unified7dFable, 0.3);
  assert.equal(am2.accounts[0].quota.unified7dFableReset, 888);
});

// ── updateQuota: Fable weekly from response headers ───────────

test('updateQuota records the Fable weekly bucket from the 7d_oi header', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const reset = Math.floor((Date.now() + 3600_000) / 1000);
  am.updateQuota(0, {
    'anthropic-ratelimit-unified-7d-utilization': '0.56',
    'anthropic-ratelimit-unified-7d-reset': String(reset),
    'anthropic-ratelimit-unified-7d_oi-utilization': '1.01',   // Fable, in overage
    'anthropic-ratelimit-unified-7d_oi-reset': String(reset),
  });
  const q = am.accounts[0].quota;
  assert.equal(q.unified7d, 0.56);
  assert.equal(q.unified7dFable, 1.01);                        // stored as a 0-1 fraction, can exceed 1
  assert.equal(q.unified7dFableReset, reset * 1000);           // seconds → ms
});

// ── model-aware selection: Fable exhaustion is model-scoped ───

test('isFableModel / parseRequestModel', () => {
  assert.equal(isFableModel('claude-fable-5'), true);
  assert.equal(isFableModel('claude-opus-4-8'), false);
  assert.equal(isFableModel(null), false);
  assert.equal(parseRequestModel(Buffer.from('{"model":"claude-fable-5","max_tokens":1}')), 'claude-fable-5');
  assert.equal(parseRequestModel('{ "model" : "claude-opus-4-8" }'), 'claude-opus-4-8');
  assert.equal(parseRequestModel('{"max_tokens":1}'), null);
  assert.equal(parseRequestModel(null), null);
});

test('a Fable-exhausted account is skipped for Fable but used for other models', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  // Account a: Fable weekly spent (from a prior 429's 7d_oi header); everything else fine.
  am.updateQuota(0, {
    'anthropic-ratelimit-unified-7d_oi-utilization': '1.01',
    'anthropic-ratelimit-unified-7d_oi-reset': String(Math.floor((Date.now() + 3600_000) / 1000)),
  });
  am.currentIndex = 0;

  // A Fable request must NOT land on the exhausted account…
  const forFable = am.getActiveAccount(null, 'claude-fable-5');
  assert.equal(forFable.name, 'b');

  // …but a non-Fable request still uses it (its Fable cap is irrelevant).
  am.currentIndex = 0;
  const forOpus = am.getActiveAccount(null, 'claude-opus-4-8');
  assert.equal(forOpus.name, 'a');

  // No model context → behaves as before (account a is available).
  am.currentIndex = 0;
  assert.equal(am.getActiveAccount().name, 'a');
});

test('all accounts Fable-exhausted → no account for a Fable request', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  const reset = String(Math.floor((Date.now() + 3600_000) / 1000));
  for (const i of [0, 1]) am.updateQuota(i, {
    'anthropic-ratelimit-unified-7d_oi-utilization': '1.0',
    'anthropic-ratelimit-unified-7d_oi-reset': reset,
  });
  // Probe is throttled off by default here, so a Fable request finds nothing…
  assert.equal(am.getActiveAccount(null, 'claude-fable-5'), null);
  // …while an Opus request is unaffected.
  assert.ok(am.getActiveAccount(null, 'claude-opus-4-8'));
});

// ── Prober ────────────────────────────────────────────────────

test('prober probes oauth accounts and applies the usage data', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  let calls = 0;
  const probeFn = async () => { calls++; return { fiveHour: { utilization: 0.1, resetAt: 1000 }, sevenDay: { utilization: 0.2, resetAt: 2000 } }; };
  const prober = new Prober(am, { intervalMs: 0, probeFn, log: () => {}, ownCoordinator: true });
  await prober.probeAll();
  assert.equal(calls, 1);
  assert.equal(am.accounts[0].quota.unified5h, 0.1);
  assert.equal(am.accounts[0].quota.unified7d, 0.2);
});

test('prober skips API-key accounts', async () => {
  const am = new AccountManager([{ name: 'k', type: 'apikey', apiKey: 'sk' }], 0.98);
  let calls = 0;
  const prober = new Prober(am, { intervalMs: 0, probeFn: async () => { calls++; return {}; }, log: () => {}, ownCoordinator: true });
  await prober.probeAll();
  assert.equal(calls, 0);
});

test('prober retries once on a 401', async () => {
  const am = new AccountManager([oauth('a')], 0.98); // no refreshToken → ensureTokenFresh is a no-op
  let calls = 0;
  const probeFn = async () => {
    calls++;
    if (calls === 1) return { error: 'HTTP 401', status: 401 };
    return { sevenDay: { utilization: 0.3, resetAt: 5000 } };
  };
  const prober = new Prober(am, { intervalMs: 0, probeFn, log: () => {}, ownCoordinator: true });
  await prober.probeAll();
  assert.equal(calls, 2);
  assert.equal(am.accounts[0].quota.unified7d, 0.3);
});
test('prober status records account probe results', async () => {
  const am = new AccountManager([oauth('a'), { name: 'k', type: 'apikey', apiKey: 'sk' }], 0.98);
  const prober = new Prober(am, {
    intervalMs: 300_000,
    probeFn: async () => ({ sevenDay: { utilization: 0.3, resetAt: 5000 } }),
    log: () => {},
    ownCoordinator: true,
  });

  await prober.probeAll();
  const status = prober.getStatus();
  assert.equal(status.enabled, true);
  assert.equal(status.intervalSeconds, 300);
  assert.equal(status.accounts[0].name, 'a');
  assert.equal(status.accounts[0].status, 'ok');
  assert.equal(typeof status.accounts[0].lastProbedAt, 'string');
  assert.equal(status.accounts[1].status, 'not-applicable');
});

// Regression, 2026-07-30: measured 0 of 6 accounts ever probed across 30min of
// uptime while the 5-minute schedule kept firing. MaintenanceCoordinator._drain
// reserved a normal request slot for every job and gave up (timeoutMs 0) when it
// could not get one — so an over-threshold account, which fails _isAvailable, was
// never probed at all. That is exactly backwards: the /api/oauth/usage read is the
// only zero-token way to learn an exhausted account recovered, and its exclusion is
// what makes the probe valuable. Slot sharing is still preserved when a slot is
// obtainable (test/warmer.test.js pins inflight===1 for an available account).
test('the zero-spend quota probe still runs for an account over its quota threshold', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.updateQuota(0, { // weekly spent → excluded from rotation
    'anthropic-ratelimit-unified-7d-utilization': '1',
    'anthropic-ratelimit-unified-7d-reset': String(Math.floor((Date.now() + 4 * 86400_000) / 1000)),
  });
  assert.equal(am._isAvailable(am.accounts[0]), false, 'precondition: account is excluded from rotation');
  // The probe's observation must be strictly NEWER than the header one, or
  // observeQuotaField drops it: on an observedAt tie the higher-priority source wins
  // and response headers (3) outrank the usage endpoint (2). Without this gap the two
  // writes can land in the same millisecond and the assertion below becomes a coin
  // flip — which is exactly how it was first committed.
  await new Promise(r => setTimeout(r, 2));

  let calls = 0;
  const prober = new Prober(am, {
    intervalMs: 0,
    // Assert on the probe function itself, not getStatus(): a call count cannot be
    // faked by a bookkeeping bug, so this isolates admission from recording.
    probeFn: async () => { calls++; return { sevenDay: { utilization: 0.42, resetAt: Date.now() + 3600_000 } }; },
    log: () => {},
    ownCoordinator: true,
  });
  await prober.probeAll();

  assert.equal(calls, 1, 'an exhausted account must still be probed — it spends no tokens');
  assert.equal(am.accounts[0].quota.unified7d, 0.42, 'the probe corrected the stale exhaustion');
});

test('the zero-spend quota probe still runs while the account is at its concurrency cap', async () => {
  const am = new AccountManager([oauth('a')], 0.98, { maxConcurrent: 1 });
  am.updateQuota(0, { // measured and well under threshold → available, just busy
    'anthropic-ratelimit-unified-5h-utilization': '0.1',
    'anthropic-ratelimit-unified-5h-reset': String(Math.floor((Date.now() + 3600_000) / 1000)),
  });
  const held = await am.acquireAccount(null, 0);
  assert.ok(held, 'precondition: ordinary traffic holds the only slot');
  assert.equal(await am.acquireAccount(null, 0), null, 'precondition: the account is at its cap');

  let calls = 0;
  const prober = new Prober(am, {
    intervalMs: 0,
    probeFn: async () => { calls++; return { sevenDay: { utilization: 0.5, resetAt: Date.now() + 3600_000 } }; },
    log: () => {},
    ownCoordinator: true,
  });
  await prober.probeAll();
  am.releaseAccount(held);

  assert.equal(calls, 1, 'a saturated account must still be probed — the usage read needs no request slot');
  assert.equal(am.accounts[0].quota.unified7d, 0.5);
  assert.ok(am.accounts[0].inflight <= am.accounts[0].maxConcurrent, 'and the cap invariant still holds');
});

// Measured on the live proxy: server up at 11:23:00Z, first probe at 11:28:00Z — a
// full interval with every account's quota unread, right after a restart restored
// those values from disk. reschedule()'s `immediate: !wasOn` default cannot fire at
// startup because the constructor already set intervalMs, so `wasOn` is always true
// on that path; the flag only ever fired when the probe was switched on from 0 at
// runtime. start() now asks for the immediate run explicitly.
test('the quota probe runs once at startup instead of waiting out the first interval', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  let calls = 0;
  const prober = new Prober(am, {
    intervalMs: 300_000, // the real default; the test must not wait for it
    probeFn: async () => { calls++; return { sevenDay: { utilization: 0.3, resetAt: Date.now() + 3600_000 } }; },
    log: () => {},
    ownCoordinator: true,
  });

  try {
    prober.start();
    await new Promise(r => setTimeout(r, 20));
    assert.equal(calls, 1, 'a restart must not leave quota unread for a whole interval');
    assert.equal(am.accounts[0].quota.unified7d, 0.3);
  } finally {
    prober.stop();
  }
});

test('prober refreshes expired token before probing', async () => {
  const am = new AccountManager(
    [oauth('a', { refreshToken: 'refresh', expiresAt: Date.now() - 1000 })],
    0.98,
    { refreshFn: async () => ({ accessToken: 'fresh', refreshToken: 'refresh2', expiresAt: Date.now() + 3600_000 }) },
  );
  let token = null;
  const prober = new Prober(am, {
    intervalMs: 0,
    probeFn: async credential => {
      token = credential;
      return { sevenDay: { utilization: 0.3, resetAt: 5000 } };
    },
    log: () => {},
    ownCoordinator: true,
  });

  await prober.probeAll();
  assert.equal(token, 'fresh');
});
