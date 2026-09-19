import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

// Drive an account to a "soft" exhausted state: utilization at/above the switch
// threshold with a reset still in the future (so it isn't cleared as stale).
function exhaust(account, utilization) {
  account.quota.unified7d = utilization;
  account.quota.unified7dReset = Date.now() + 3600_000;
}

test('finite priority cannot authorize spending over exhausted quota', () => {
  const accounts = [oauth('ranked', { priority: 100 }), oauth('unranked')];
  const am = new AccountManager(accounts, 0.98);
  exhaust(am.accounts[0], 0.99);
  exhaust(am.accounts[1], 0.985);

  assert.equal(am.getActiveAccount(), null);
});
test('when every account is over threshold, ordinary routing refuses without a spending probe', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  exhaust(am.accounts[0], 0.99);
  exhaust(am.accounts[1], 0.985);

  const picked = am.getActiveAccount();
  assert.equal(picked, null);
  assert.equal(am.getActiveAccount(null, 'claude-sonnet-5'), null);
  assert.equal(am._nextProbeAt, 0, 'ordinary routing never consumes a probe slot');
});

test('elapsed probe interval does not authorize ordinary spending', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  exhaust(am.accounts[0], 0.99);
  exhaust(am.accounts[1], 0.99);

  assert.equal(am.getActiveAccount(), null);
  // A second request inside the interval must refuse (synthetic 429), not probe again.
  assert.equal(am.getActiveAccount(), null);

  // The metadata prober's interval is not a request admission bypass.
  am._nextProbeAt = Date.now() - 1;
  assert.equal(am.getActiveAccount(), null);
});

test('a hard upstream rate-limit is respected — no probe, synthetic 429 stands', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  am.markRateLimited(0, 300);
  am.markRateLimited(1, 300);
  assert.equal(am.getActiveAccount(), null);
});

test('an expired unrelated reset cannot bypass a live exhausted weekly window', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  exhaust(am.accounts[0], 0.99);
  am.accounts[0].quota.unified5hReset = Date.now() - 1;
  assert.equal(am.getActiveAccount(null, 'claude-sonnet-5'), null);
  assert.equal(am.accounts[0].quota.unified7d, 0.99);
});

test('disabled accounts are never used as a probe target', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  exhaust(am.accounts[0], 0.99);
  exhaust(am.accounts[1], 0.99);
  am.accounts[0].disabled = true;
  am.accounts[1].disabled = true;
  assert.equal(am.getActiveAccount(), null);
});

test('a probe refreshing healthy quota restores normal (non-throttled) selection', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  exhaust(am.accounts[0], 0.99);

  const probe = am.getActiveAccount();
  assert.equal(probe, null, 'ordinary traffic waits for fresh evidence');
  // Simulate the upstream response showing real headroom.
  am.updateQuota(0, { 'anthropic-ratelimit-unified-7d-utilization': '0.10' });

  // Now the account is available the normal way, with no throttle gating.
  assert.equal(am.getActiveAccount().name, 'a');
});
