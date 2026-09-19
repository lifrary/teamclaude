import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';
import { createCanonicalState, rekeyCanonicalState, getStatePath } from '../src/config.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

test('Codex provider ID and canonical identity coexist without leaking credentials', () => {
  const account = oauth('codex', { provider: 'codex', accountId: 'seat-123', accessToken: 'secret-access' });
  const am = new AccountManager([account]);
  const live = am.accounts[0];
  assert.equal(live.accountId, 'seat-123');
  assert.equal(typeof live.canonicalAccountId, 'object');
  assert.equal(Object.isFrozen(live.canonicalAccountId), true);
  live.quota.unified7d = 0.45;
  const state = am.exportCanonicalState();
  assert.deepEqual(Object.keys(state.accounts), [live.accountIdKey]);
  assert.equal(JSON.stringify(state).includes('secret-access'), false);
  const restored = new AccountManager([{ ...account, name: 'renamed' }]);
  restored.restoreCanonicalState(state);
  assert.equal(restored.accounts[0].quota.unified7d, 0.45);
});

test('canonical profile and adaptive learning survive exact-identity restore', () => {
  const config = oauth('a', { accountUuid: 'p1', orgUuid: 'org' });
  const am = new AccountManager([config]);
  am.applyProfileData(am.accounts[0], { organizationType: 'claude_team', seatTier: 'team_standard' });
  const now = Date.now();
  am.burnRateLearner.observeUtilization(0, 'unified7d', 0.1, now - 300_000);
  am.burnRateLearner.observeUtilization(0, 'unified7d', 0.2, now);
  am.concurrencyLearner.caps.set(0, 3.5);
  const state = createCanonicalState(am.exportCanonicalState());
  const restored = new AccountManager([config]);
  restored.restoreCanonicalState(state);
  assert.equal(restored.accounts[0].seatTier, 'team_standard');
  assert.equal(restored.burnRateLearner.reserve(0, 'unified7d'), am.burnRateLearner.reserve(0, 'unified7d'));
  assert.equal(restored.concurrencyLearner.cap(0), 3.5);
  const other = new AccountManager([{ ...config, orgUuid: 'different-org' }]);
  other.restoreCanonicalState(state);
  assert.equal(other.accounts[0].seatTier, null);
  assert.equal(other.concurrencyLearner.export(0), null);
});

test('response ownership wins equal-time usage, but a newer probe owns its independent fields', () => {
  const am = new AccountManager([oauth('a')]);
  const account = am.accounts[0];
  const originalNow = Date.now;
  let now = originalNow();
  Date.now = () => now;
  try {
    am.updateQuota(account, {
      'anthropic-ratelimit-unified-5h-utilization': '0.6',
      'anthropic-ratelimit-unified-5h-reset': String((now + 3600_000) / 1000),
    });
    am.applyUsageData(account, { fiveHour: { utilization: 0.2 } });
    assert.equal(account.quota.unified5h, 0.6);
    now++;
    am.applyUsageData(account, { fiveHour: { utilization: 0.3 } });
    assert.equal(account.quota.unified5h, 0.3);
    assert.equal(account.quota.unified5hReset, null, 'a new reading cannot borrow an older reset');
    const snapshot = am.exportCanonicalState();
    assert.equal('observations' in snapshot.accounts[account.accountIdKey].quota, false);
    assert.equal('unifiedStatus' in snapshot.accounts[account.accountIdKey].quota, false);
  } finally {
    Date.now = originalNow;
  }
});

test('a modelWeekly-only Fable window gates Fable without blocking Sonnet', () => {
  const am = new AccountManager([oauth('a')]);
  const account = am.accounts[0];
  account.quota.modelWeekly['7d_oi'] = { utilization: 1, reset: Date.now() + 3600_000 };
  assert.equal(am._isAvailable(account, 'claude-fable-5'), false);
  assert.equal(am._isAvailable(account, 'claude-sonnet-4-6'), true);
  am.applyUsageData(account, { sevenDayFable: { utilization: 0.1, resetAt: Date.now() + 3600_000 } });
  assert.equal(am._isAvailable(account, 'claude-fable-5'), true, 'new probe evidence supersedes the header bucket');
});

test('exportCanonicalState persists credential-free state under exact org-aware identities', () => {
  const am = new AccountManager([
    oauth('a@x.com (Acme)', { accessToken: 'access-secret', refreshToken: 'refresh-secret', accountUuid: 'p1', orgUuid: 'o1' }),
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
  ], 0.98);
  am.accounts[0].quota.unified7d = 0.42;
  const state = am.exportCanonicalState();

  assert.deepEqual(Object.keys(state.accounts).sort(), ['u:p1:o:o1', 'u:p1:o:o2']);
  assert.deepEqual(Object.keys(state.accounts['u:p1:o:o1']).sort(), ['quota', 'usage']);
  assert.equal(state.accounts['u:p1:o:o1'].quota.unified7d, 0.42);
  assert.equal(JSON.stringify(state).includes('access-secret'), false);
  assert.equal(JSON.stringify(state).includes('refresh-secret'), false);
});

test('quota survives a canonical export → restore round-trip', () => {
  const am1 = new AccountManager([oauth('a', { accountUuid: 'p1', orgUuid: 'o1' })], 0.98);
  const future = Date.now() + 3600_000;
  Object.assign(am1.accounts[0].quota, { unified5h: 0.3, unified7d: 0.6, unified7dReset: future });

  const am2 = new AccountManager([oauth('a', { accountUuid: 'p1', orgUuid: 'o1' })], 0.98);
  am2.restoreCanonicalState(am1.exportCanonicalState());

  assert.equal(am2.accounts[0].quota.unified5h, 0.3);
  assert.equal(am2.accounts[0].quota.unified7d, 0.6);
  assert.equal(am2.accounts[0].quota.unified7dReset, future);
  assert.equal(am2.accounts[0].probing, false); // weekly window known → not probing
});

test('canonical restore matches the complete org-aware identity, not array position', () => {
  const am1 = new AccountManager([
    oauth('a@x.com (Acme)', { accountUuid: 'p1', orgUuid: 'o1' }),
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
  ], 0.98);
  am1.accounts[0].quota.unified7d = 0.1; // Acme
  am1.accounts[1].quota.unified7d = 0.9; // Personal
  const saved = am1.exportCanonicalState();

  // Reverse the order in the new manager — restore must still match by org.
  const am2 = new AccountManager([
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
    oauth('a@x.com (Acme)', { accountUuid: 'p1', orgUuid: 'o1' }),
  ], 0.98);
  am2.restoreCanonicalState(saved);

  assert.equal(am2.accounts[0].quota.unified7d, 0.9); // Personal
  assert.equal(am2.accounts[1].quota.unified7d, 0.1); // Acme
});

test('a canonically restored window whose reset already passed is cleared on first use', () => {
  const source = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  source.accounts[0].quota.unified7d = 0.5;
  source.accounts[0].quota.unified7dReset = 1000; // reset far in the past
  const am = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am.restoreCanonicalState(source.exportCanonicalState());
  assert.equal(am.accounts[0].quota.unified7d, 0.5); // restored...
  am.refreshExpiredQuotas();
  assert.equal(am.accounts[0].quota.unified7d, null); // ...then cleared as stale
});

test('restoreCanonicalState ignores a missing payload', () => {
  const am = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am.restoreCanonicalState(undefined);
  am.restoreCanonicalState(null);
  assert.equal(am.accounts[0].quota.unified7d, null); // unchanged, no throw
});

test('getStatePath sits beside the config as a .state.json sibling', () => {
  const prev = process.env.TEAMCLAUDE_CONFIG;
  process.env.TEAMCLAUDE_CONFIG = '/tmp/teamclaude-xyz.json';
  try {
    assert.equal(getStatePath(), '/tmp/teamclaude-xyz.state.json');
  } finally {
    if (prev === undefined) delete process.env.TEAMCLAUDE_CONFIG;
    else process.env.TEAMCLAUDE_CONFIG = prev;
  }
});
test('canonical quota state is keyed by AccountId and rejects a replaced same-name identity', () => {
  const first = new AccountManager([
    oauth('same@example.com', { accountUuid: 'old', orgUuid: 'org' }),
  ], 0.98);
  first.accounts[0].quota.unified7d = 0.61;
  first.accounts[0].usage.totalRequests = 3;
  const state = first.exportCanonicalState();

  assert.deepEqual(Object.keys(state.accounts), ['u:old:o:org']);
  assert.deepEqual(Object.keys(state.accounts['u:old:o:org']).sort(), ['quota', 'usage']);

  const replaced = new AccountManager([
    oauth('same@example.com', { accountUuid: 'new', orgUuid: 'org' }),
  ], 0.98);
  replaced.restoreCanonicalState(state);
  assert.equal(replaced.accounts[0].quota.unified7d, null);
  assert.equal(replaced.accounts[0].usage.totalRequests, 0);
});
test('replaceAccount publishes a new canonical object while an in-flight object drains', () => {
  const am = new AccountManager([
    oauth('same@example.com', { accountUuid: 'p1', orgName: 'Acme' }),
  ], 0.98);
  const held = am.accounts[0];
  held.inFlight = 1;
  held.quota.unified7d = 0.42;

  const replacement = am.replaceAccount(held, oauth('same@example.com', {
    accountUuid: 'p1',
    orgUuid: 'o1',
  }));

  assert.notEqual(replacement, held);
  assert.equal(held.accountIdKey, 'u:p1:n:acme');
  assert.equal(replacement.accountIdKey, 'u:p1:o:o1');
  assert.equal(replacement.quota.unified7d, 0.42);
  am.releaseAccount(held);
  assert.equal(held.inFlight, 0);
  assert.equal(replacement.inFlight, 0);
});
test('org-name rekey preserves credential-free quota state for serialized restart recovery', () => {
  const before = createCanonicalState({
    accounts: { 'u:p1:n:acme': { quota: { unified7d: 0.42 }, usage: { totalRequests: 3 } } },
    activeAccountId: 'u:p1:n:acme',
  });
  const reloaded = JSON.parse(JSON.stringify(before));
  const after = rekeyCanonicalState(reloaded, 'u:p1:n:acme', 'u:p1:o:o1');
  assert.deepEqual(after.accounts['u:p1:o:o1'], before.accounts['u:p1:n:acme']);
  assert.equal(after.activeAccountId, 'u:p1:o:o1');
  assert.doesNotMatch(JSON.stringify(after), /accessToken|refreshToken|apiKey/);
});

test('exportQuotaState carries only persistable fields and identity, no credentials', () => {
  const am = new AccountManager([oauth('a', { accountUuid: 'p1', orgUuid: 'o1', orgName: 'Acme' })], 0.98);
  am.accounts[0].quota.unified7d = 0.42;
  const [entry] = am.exportQuotaState();

  // `provider` and `accountId` are identity, not credentials: they are what
  // identifies an account that has no Anthropic uuid to be matched by.
  assert.deepEqual(
    Object.keys(entry).sort(),
    ['accountUuid', 'accountId', 'provider', 'name', 'orgName', 'orgUuid', 'profile', 'quota', 'adaptive'].sort(),
  );
  assert.equal(entry.accountUuid, 'p1');
  assert.equal(entry.provider, 'anthropic');
  assert.equal(entry.quota.unified7d, 0.42);
  // Transient/credential fields must not leak.
  assert.ok(!('probing' in entry.quota));
  assert.ok(!('rateLimitedUntil' in entry.quota));
  assert.ok(!('credential' in entry));
  assert.ok(!('accessToken' in entry));
});

test('adaptive burn and concurrency learning survive an identity-matched restart', () => {
  const am1 = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  const t0 = Date.now();
  am1.burnRateLearner.observeUtilization(0, 'unified7d', 0.10, t0);
  am1.burnRateLearner.observeUtilization(0, 'unified7d', 0.20, t0 + 5 * 60_000);
  am1.concurrencyLearner.caps.set(0, 3.5);
  const reserve = am1.burnRateLearner.reserve(0, 'unified7d');

  const am2 = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am2.restoreQuotaState(am1.exportQuotaState());

  assert.equal(am2.burnRateLearner.reserve(0, 'unified7d'), reserve);
  assert.equal(am2.concurrencyLearner.cap(0), 3.5);
});

test('quota survives an export → restore round-trip', () => {
  const am1 = new AccountManager([oauth('a', { accountUuid: 'p1', orgUuid: 'o1' })], 0.98);
  const future = Date.now() + 3600_000;
  Object.assign(am1.accounts[0].quota, { unified5h: 0.3, unified7d: 0.6, unified7dReset: future });

  const am2 = new AccountManager([oauth('a', { accountUuid: 'p1', orgUuid: 'o1' })], 0.98);
  am2.restoreQuotaState(am1.exportQuotaState());

  assert.equal(am2.accounts[0].quota.unified5h, 0.3);
  assert.equal(am2.accounts[0].quota.unified7d, 0.6);
  assert.equal(am2.accounts[0].quota.unified7dReset, future);
  assert.equal(am2.accounts[0].probing, false); // weekly window known → not probing
});

test('quota tier metadata survives an export → restore round-trip', () => {
  const am1 = new AccountManager([oauth('a', {
    accountUuid: 'p1', organizationType: 'claude_team',
    rateLimitTier: 'default_raven', seatTier: 'team_standard',
  })], 0.98);
  const saved = am1.exportQuotaState();
  const am2 = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);

  am2.restoreQuotaState(saved);

  assert.equal(am2.accounts[0].organizationType, 'claude_team');
  assert.equal(am2.accounts[0].rateLimitTier, 'default_raven');
  assert.equal(am2.accounts[0].seatTier, 'team_standard');
});

test('restore matches by identity, not array position', () => {
  const am1 = new AccountManager([
    oauth('a@x.com (Acme)', { accountUuid: 'p1', orgUuid: 'o1' }),
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
  ], 0.98);
  am1.accounts[0].quota.unified7d = 0.1; // Acme
  am1.accounts[1].quota.unified7d = 0.9; // Personal
  const saved = am1.exportQuotaState();

  // Reverse the order in the new manager — restore must still match by org.
  const am2 = new AccountManager([
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
    oauth('a@x.com (Acme)', { accountUuid: 'p1', orgUuid: 'o1' }),
  ], 0.98);
  am2.restoreQuotaState(saved);

  assert.equal(am2.accounts[0].quota.unified7d, 0.9); // Personal
  assert.equal(am2.accounts[1].quota.unified7d, 0.1); // Acme
});

test('a restored window whose reset already passed is cleared on first use', () => {
  const am = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am.restoreQuotaState([
    { accountUuid: 'p1', quota: { unified7d: 0.5, unified7dReset: 1000 } }, // reset far in the past
  ]);
  assert.equal(am.accounts[0].quota.unified7d, 0.5); // restored...
  am.refreshExpiredQuotas();
  assert.equal(am.accounts[0].quota.unified7d, null); // ...then cleared as stale
});

test('restoreQuotaState ignores a non-array / missing payload', () => {
  const am = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am.restoreQuotaState(undefined);
  am.restoreQuotaState(null);
  assert.equal(am.accounts[0].quota.unified7d, null); // unchanged, no throw
});
