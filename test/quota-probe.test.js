import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUsageBucket, findScopedWeeklyLimit, normalizeUsagePayload } from '../src/oauth.js';
import { AccountManager, isFableModel, parseRequestModel } from '../src/account-manager.js';
import { Prober, MAX_PROBE_INTERVAL_MS } from '../src/prober.js';

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

// ── normalizeUsagePayload: what a probe can conclude ──────────

// Shape copied from a real Max payload: the account has a Fable cap it has not
// touched (percent 0, no window started) and no Sonnet cap at all.
const USAGE_PAYLOAD = {
  five_hour: { utilization: 15, resets_at: '2026-09-02T13:59:59Z' },
  seven_day: { utilization: 6, resets_at: '2026-09-04T03:59:59Z' },
  seven_day_sonnet: null,
  limits: [
    { kind: 'session', group: 'session', percent: 15, scope: null },
    { kind: 'weekly_all', group: 'weekly', percent: 6, scope: null },
    { kind: 'weekly_scoped', group: 'weekly', percent: 0, resets_at: null,
      scope: { model: { id: null, display_name: 'Fable' } } },
  ],
};

test('a listed-but-unused family reads as zero with no window', () => {
  const u = normalizeUsagePayload(USAGE_PAYLOAD);
  assert.equal(u.sevenDayFable.utilization, 0);
  assert.equal(u.sevenDayFable.resetAt, null);   // the window has not started
  assert.equal(u.sevenDaySonnet, null);          // this account has no Sonnet cap
  assert.equal(u.scopedWeeklyListed, true);      // …and upstream said so explicitly
});

test('Sonnet is read from the enumeration too, not only the legacy key', () => {
  const u = normalizeUsagePayload({ limits: [
    { kind: 'weekly_scoped', group: 'weekly', percent: 40, resets_at: '2026-09-04T03:59:59Z',
      scope: { model: { display_name: 'Sonnet' } } },
  ]});
  assert.equal(u.sevenDaySonnet.utilization, 0.4);
  // The legacy top-level key still wins where a plan still reports it.
  assert.equal(normalizeUsagePayload({ seven_day_sonnet: { utilization: 70 }, limits: [] }).sevenDaySonnet.utilization, 0.7);
});

test('a payload with no enumeration concludes nothing about families', () => {
  const u = normalizeUsagePayload({ five_hour: { utilization: 3 } });
  assert.equal(u.sevenDayFable, null);
  assert.equal(u.sevenDaySonnet, null);
  assert.equal(u.scopedWeeklyListed, false);
});

// ── applyUsageData: the probe revalidates family buckets ──────

// Put an account in the state #167 described: a spent family reading whose own
// reset is days out, so nothing expires it and selection refuses the family.
function sealFable(am, { utilization = 0.99 } = {}) {
  const q = am.accounts[0].quota;
  q.unified7dFable = utilization;
  q.unified7dFableReset = Date.now() + 7 * 24 * 3600_000;
  q.unified7dFableSeenAt = Date.now() - 60_000;
  return q;
}

test('a probe that reports the family available breaks the seal', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const q = sealFable(am);
  assert.equal(am.getActiveAccount(null, 'claude-fable-5'), null);   // refusing Fable

  am.applyUsageData(0, normalizeUsagePayload(USAGE_PAYLOAD));

  assert.equal(q.unified7dFable, 0);
  // The stale reset went with it: it was the shared weekly window, copied in by
  // the header path, and keeping it would misdate the bar and misrank selection.
  assert.equal(q.unified7dFableReset, null);
  assert.ok(q.unified7dFableSeenAt > Date.now() - 5000);             // freshly confirmed
  assert.equal(am.getActiveAccount(null, 'claude-fable-5').name, 'a');
});

test('a family missing from an enumeration is cleared, not kept', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const q = sealFable(am);
  // Upstream listed this account's scoped weekly caps and Fable was not among
  // them — the cap is gone, so the family falls back to the shared weekly gate.
  am.applyUsageData(0, normalizeUsagePayload({ limits: [
    { kind: 'weekly_all', group: 'weekly', percent: 6, scope: null },
  ]}));
  assert.equal(q.unified7dFable, null);
  assert.equal(q.unified7dFableReset, null);
  assert.equal(q.unified7dFableSeenAt, null);
  assert.equal(am.getActiveAccount(null, 'claude-fable-5').name, 'a');
});

test('a payload that enumerates nothing leaves the reading alone', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const q = sealFable(am);
  const reset = q.unified7dFableReset;
  // No enumeration: the family is missing because we cannot see it, not because
  // upstream says it is gone. Clearing here would drop a real cap and overspend.
  am.applyUsageData(0, normalizeUsagePayload({ five_hour: { utilization: 3 } }));
  assert.equal(q.unified7dFable, 0.99);
  assert.equal(q.unified7dFableReset, reset);
  // The staleness floor still frees it later; that path is unchanged.
});

test('a failed probe is not evidence', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const q = sealFable(am);
  am.applyUsageData(0, { error: 'HTTP 503', status: 503 });
  assert.equal(q.unified7dFable, 0.99);
  assert.equal(am.getActiveAccount(null, 'claude-fable-5'), null);
});

test('a probe that reports the family still spent keeps it spent', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const q = sealFable(am);
  const at = Math.floor((Date.now() + 48 * 3600_000) / 1000) * 1000;
  am.applyUsageData(0, normalizeUsagePayload({ limits: [
    { kind: 'weekly_scoped', group: 'weekly', percent: 99, resets_at: new Date(at).toISOString(),
      scope: { model: { display_name: 'Fable' } } },
  ]}));
  assert.equal(q.unified7dFable, 0.99);
  assert.equal(q.unified7dFableReset, at);        // now dated by its OWN window
  assert.equal(am.getActiveAccount(null, 'claude-fable-5'), null);
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

test('prober learns missing quota tier metadata with the first quota refresh', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const prober = new Prober(am, {
    ownCoordinator: true,
    intervalMs: 0,
    probeFn: async () => ({ sevenDay: { utilization: 0.2, resetAt: 2000 } }),
    profileFn: async () => ({
      organizationType: 'claude_team', rateLimitTier: 'default_raven',
      seatTier: 'team_standard', hasClaudeMax: true, hasClaudePro: false,
    }),
    log: () => {},
  });

  await prober.probeAll();

  assert.equal(am.accounts[0].organizationType, 'claude_team');
  assert.equal(am.accounts[0].rateLimitTier, 'default_raven');
  assert.equal(am.accounts[0].seatTier, 'team_standard');
  assert.equal(am.getQuotaSummary().accounts[0].tier.weight, 1);
});

// A third-party backend account is typed `oauth` with a static token (the
// documented DeepSeek/GLM pattern), so a type check alone sends THAT provider's
// key to api.anthropic.com every cycle — which answers 429, leaving a permanent
// probe error on an account that is serving traffic normally.
test('prober never sends a third-party key to the Anthropic usage endpoint', async () => {
  const am = new AccountManager([
    oauth('claude'),
    { ...oauth('deepseek'), upstream: 'https://api.deepseek.com/anthropic' },
  ], 0.98);
  const probed = [];
  const probeFn = async (token) => { probed.push(token); return { fiveHour: { utilization: 0.1, resetAt: 1 } }; };
  // The DeepSeek backend publishes its own quota, so it IS a probe target now —
  // of the backend read, which must go to its own host and never to Anthropic.
  // Stubbed: the real read would leave the test suite for the network.
  const backendRead = [];
  const backendFn = async (account) => { backendRead.push(account.name); return { error: 'stub' }; };
  await new Prober(am, { intervalMs: 0, probeFn, backendFn, log: () => {}, ownCoordinator: true }).probeAll();

  assert.deepEqual(probed, ['t-claude']);
  assert.deepEqual(backendRead, ['deepseek']);
  // …and the backend's own quota is left untouched rather than recorded as an error.
  assert.equal(am.accounts[1].quota.unified5h, null);
});

test('a third-party backend reads not-applicable, not a pending probe', () => {
  // A backend whose provider publishes nothing (see backend-quota.js). One that
  // DOES publish is probeable and reads `never` until its first cycle — covered
  // in backend-quota.test.js.
  const am = new AccountManager([
    oauth('claude'),
    { ...oauth('other'), upstream: 'https://api.example.invalid/anthropic' },
  ], 0.98);
  const rows = new Prober(am, { intervalMs: 300_000, log: () => {}, ownCoordinator: true }).getStatus().accounts;
  assert.equal(rows[0].status, 'never');            // probed, just not yet
  assert.equal(rows[1].status, 'not-applicable');   // nothing to probe, ever
});

test('prober skips API-key accounts', async () => {
  const am = new AccountManager([{ name: 'k', type: 'apikey', apiKey: 'sk' }], 0.98);
  let calls = 0;
  const prober = new Prober(am, { intervalMs: 0, probeFn: async () => { calls++; return {}; }, log: () => {}, ownCoordinator: true });
  await prober.probeAll();
  assert.equal(calls, 0);
});

test('prober sends Codex accounts only to the Codex usage endpoint', async () => {
  const am = new AccountManager([oauth('codex', { provider: 'codex', accountId: 'acct-codex' })], 0.98);
  let anthropicCalls = 0;
  let codexCalls = 0;
  const prober = new Prober(am, {
    ownCoordinator: true,
    intervalMs: 0,
    probeFn: async () => { anthropicCalls++; return { error: 'HTTP 401', status: 401 }; },
    codexProbeFn: async account => { codexCalls++; assert.equal(account.accountId, 'acct-codex'); return { sevenDay: { utilization: 0.2, resetAt: 123 } }; },
    log: () => {},
  });
  await prober.probeAll();
  assert.equal(anthropicCalls, 0);
  assert.equal(codexCalls, 1);
  assert.equal(prober.getStatus().accounts[0].status, 'ok');
  assert.equal(am.accounts[0].quota.unified7d, 0.2);
});

test('shutdown cancels Codex, backend, and profile reads without releasing live I/O capacity', async () => {
  for (const kind of ['codex', 'backend', 'profile']) {
    const extra = kind === 'codex' ? { provider: 'codex', accountId: 'acct-codex' }
      : kind === 'backend' ? { upstream: 'https://api.deepseek.com/anthropic' } : {};
    const am = new AccountManager([oauth(kind, extra)], 0.98, { maxConcurrent: 1 });
    let markStarted;
    const started = new Promise(resolve => { markStarted = resolve; });
    let settle;
    let childSignal;
    const read = signal => new Promise(resolve => {
      childSignal = signal;
      settle = resolve;
      markStarted();
    });
    const prober = new Prober(am, {
      ownCoordinator: true,
      log: () => {},
      probeFn: async () => ({}),
      codexProbeFn: (_account, { signal }) => read(signal),
      backendFn: (_account, { signal }) => read(signal),
      profileFn: (_credential, signal) => read(signal),
    });
    const probing = prober.probeAll();
    await started;
    assert.equal(am.accounts[0].inflight, 1, `${kind} read reserves capacity`);
    prober.stop();
    assert.equal(childSignal.aborted, true, `${kind} receives cancellation`);
    assert.equal(am.accounts[0].inflight, 1, `${kind} keeps capacity until I/O settles`);
    settle(null);
    await probing;
    assert.equal(am.accounts[0].inflight, 0);
    assert.equal(prober.getStatus().accounts[0].status, 'cancelled');
    assert.equal(am.accounts[0].quota.unified7d, null);
  }
});

test('prober retries once on a 401 after refreshing the rejected credential', async () => {
  let refreshes = 0;
  const am = new AccountManager([oauth('a', { refreshToken: 'refresh-a' })], 0.98, {
    refreshFn: async () => {
      refreshes++;
      return { accessToken: 'new-a', refreshToken: 'new-refresh-a', expiresAt: Date.now() + 3600_000 };
    },
  });
  let calls = 0;
  const probeFn = async token => {
    calls++;
    if (calls === 1) return { error: 'HTTP 401', status: 401 };
    assert.equal(token, 'new-a');
    return { sevenDay: { utilization: 0.3, resetAt: 5000 } };
  };
  const prober = new Prober(am, { intervalMs: 0, probeFn, log: () => {}, ownCoordinator: true });
  await prober.probeAll();
  assert.equal(calls, 2);
  assert.equal(refreshes, 1);
  assert.equal(am.accounts[0].quota.unified7d, 0.3);
});
test('prober does not resend a rejected credential when no refresh lineage exists', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  let calls = 0;
  const prober = new Prober(am, {
    ownCoordinator: true, log: () => {},
    probeFn: async () => { calls++; return { error: 'HTTP 401', status: 401 }; },
  });
  await prober.probeAll();
  assert.equal(calls, 1);
  assert.equal(prober.getStatus().accounts[0].status, 'error');
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

// Disabled is out of rotation, not out of read-only monitoring. A probe must
// neither re-enable it nor rotate its token family, including on a 401.
test('prober monitors disabled accounts without refreshing their lineage', async () => {
  let refreshes = 0;
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98, {
    refreshFn: async () => { refreshes++; throw new Error('must not refresh'); },
  });
  am.setDisabled(0, true);
  const probed = [];
  const prober = new Prober(am, { intervalMs: 0, probeFn: async cred => {
    probed.push(cred);
    return cred === 't-a' ? { error: 'HTTP 401', status: 401 } : {};
  }, log: () => {}, ownCoordinator: true });
  await prober.probeAll();
  assert.deepEqual(probed.sort(), ['t-a', 't-b']);
  assert.equal(refreshes, 0);
  assert.equal(am.accounts[0].disabled, true);
});

test('prober skips an account holding a rejected refresh token, until a new one arrives', async () => {
  let refreshes = 0;
  const am = new AccountManager(
    [oauth('a', { refreshToken: 'rt-dead', expiresAt: Date.now() - 1000 })],
    0.98,
    { refreshFn: async () => { refreshes++; const e = new Error('invalid_grant'); e.status = 400; throw e; } },
  );
  let probes = 0;
  const prober = new Prober(am, { intervalMs: 0, probeFn: async () => { probes++; return {}; }, log: () => {}, ownCoordinator: true });

  await prober.probeAll();                 // first cycle: the refresh is tried once and rejected
  assert.equal(refreshes, 1);
  assert.equal(am.accounts[0]._deadRefreshToken, 'rt-dead');
  const probesAfterRejection = probes;

  await prober.probeAll();
  await prober.probeAll();
  assert.equal(probes, probesAfterRejection, 'no token is sent for an account that needs a re-login');
  assert.equal(refreshes, 1);

  // A re-login lifts the skip: the manager's guard is keyed on the token value.
  am.updateAccountTokens(0, { accessToken: 'at-new', refreshToken: 'rt-new', expiresAt: Date.now() + 3600_000 });
  await prober.probeAll();
  assert.equal(probes, probesAfterRejection + 1);
});

// setInterval coerces a delay above 2^31-1 ms to 1 ms, which would turn an
// interval meant as "practically never" into a tight probing loop.
test('prober clamps its interval so the timer cannot overflow', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const prober = new Prober(am, { intervalMs: 0, probeFn: async () => ({}), log: () => {}, ownCoordinator: true });
  try {
    prober.reschedule(365 * 24 * 3600 * 1000);
    assert.equal(prober.intervalMs, MAX_PROBE_INTERVAL_MS);
    assert.ok(prober.intervalMs <= 2 ** 31 - 1);
    assert.equal(prober.getStatus().intervalSeconds, MAX_PROBE_INTERVAL_MS / 1000);
    assert.ok(prober.nextRunAt - Date.now() <= MAX_PROBE_INTERVAL_MS);
  } finally {
    prober.stop();
  }
  const huge = new Prober(am, { intervalMs: Number.MAX_SAFE_INTEGER, probeFn: async () => ({}), log: () => {}, ownCoordinator: true });
  assert.equal(huge.intervalMs, MAX_PROBE_INTERVAL_MS, 'the constructor clamps too');
  assert.equal(new Prober(am, { intervalMs: NaN, log: () => {}, ownCoordinator: true }).intervalMs, 0, 'a non-number is off');
});
