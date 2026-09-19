import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

// The scenario these tests guard against (reproduced live in a sandbox): a 429
// burst throttles every account with a long retry-after hold; the hold lives
// only in memory and nothing revalidates it, so teamclaude keeps refusing with
// synthetic 429s even after upstream is healthy again, until a restart wipes
// the holds. Ordinary requests never bypass a hold to spend quota; independently
// obtained upstream evidence or natural expiry restores admission.

test('within the floor, a rate-limit hold is respected verbatim (no probe)', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  am.markRateLimited(0, 3600);
  am.markRateLimited(1, 3600);
  assert.equal(am.getActiveAccount(), null, 'freshly throttled fleet must refuse');
});

test('after the floor, ordinary requests still respect an upstream hold', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  am.markRateLimited(0, 3600);
  am.markRateLimited(1, 3600);
  // Simulate the floor having elapsed (holds still far in the future).
  am.accounts[0].throttledAt = Date.now() - am.throttleProbeFloorMs - 1;
  am.accounts[1].throttledAt = Date.now() - am.throttleProbeFloorMs - 1;

  const probe = am.getActiveAccount();
  assert.equal(probe, null);
  assert.equal(am.accounts[0].status, 'throttled');

  // Model-scoped routing must respect the same hold.
  assert.equal(am.getActiveAccount(null, 'claude-sonnet-5'), null);
});

test('a non-429 response clears the hold and returns the account to rotation', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.markRateLimited(0, 3600);
  am.accounts[0].throttledAt = Date.now() - am.throttleProbeFloorMs - 1;
  const probe = am.getActiveAccount();
  assert.equal(probe, null);

  // server.js calls this on any non-429 upstream response.
  am.clearRateLimited(am.accounts[0]);
  assert.equal(am.accounts[0].status, 'active');
  assert.equal(am.accounts[0].rateLimitedUntil, null);
  assert.equal(am.accounts[0].throttledAt, null);
  // Normal selection works again with no probe gate involved.
  assert.equal(am.getActiveAccount()?.name, 'a');
});

test('fresh upstream 429 evidence re-arms the hold without admitting a spending probe', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.markRateLimited(0, 3600);
  am.accounts[0].throttledAt = Date.now() - am.throttleProbeFloorMs - 1;
  assert.equal(am.getActiveAccount(), null, 'elapsed floor is not admission');

  // Upstream said 429 again: forwardRequest re-arms via markRateLimited.
  am.markRateLimited(0, 3600);
  am._nextProbeAt = 0; // even with the probe interval open...
  assert.equal(am.getActiveAccount(), null, '...the fresh floor blocks an immediate re-probe');
});

test('clearRateLimited is a no-op on accounts that are not throttled', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.accounts[0].status = 'error';
  am.clearRateLimited(0);
  assert.equal(am.accounts[0].status, 'error', 'must not resurrect an errored account');
  am.clearRateLimited(99); // out of range: must not throw
});

test('constructor floor option is honored', () => {
  const am = new AccountManager([oauth('a')], 0.98, { throttleProbeFloorMs: 5 });
  am.markRateLimited(0, 3600);
  assert.equal(am.getActiveAccount(), null, 'inside the tiny floor');
  am.accounts[0].throttledAt = Date.now() - 6;
  assert.equal(am.getActiveAccount(), null, 'past the tiny floor still cannot spend');
  assert.equal(am.throttleProbeFloorMs, 5);
});

test('natural hold expiry still clears state fully', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.markRateLimited(0, 1);
  am.accounts[0].rateLimitedUntil = Date.now() - 1; // expired
  const acct = am.getActiveAccount();
  assert.equal(acct?.name, 'a');
  assert.equal(am.accounts[0].throttledAt, null, 'expiry must reset throttledAt too');
});
