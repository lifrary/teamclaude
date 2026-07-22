import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const pin = account => ({ pinnedAccount: account });

test('_rampCap grows during its window and lifts after it', () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    stormRamp: { startConc: 1, stepConc: 2, stepMs: 100, windowMs: 1000, pollMs: 5 },
  });
  const account = am.accounts[0];
  account.rampStartedAt = 1000;
  assert.equal(am._rampCap(account, 1000), 1);
  assert.equal(am._rampCap(account, 1100), 3);
  assert.equal(am._rampCap(account, 2000), Infinity);
});

test('canonical acquire queues a pinned request behind its capped account and reserves it on release', async () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98, {
    maxConcurrent: 1, queueTimeoutMs: 500, maxQueueDepth: 1,
  });
  const target = am.accounts[0];
  const first = await am.acquireAccount(null, 500, null, null, pin(target));
  const pending = am.acquireAccount(null, 500, null, null, pin(target));
  await sleep(20);
  assert.equal(am.accounts[1].inFlight, 0, 'a pin must not spill to another account');
  am.releaseAccount(first);
  const second = await pending;
  assert.equal(second, target);
  am.releaseAccount(second);
});

test('canonical acquire times out a capped pinned request without reserving another account', async () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98, { maxConcurrent: 1, queueTimeoutMs: 30 });
  const target = am.accounts[0];
  const first = await am.acquireAccount(null, 30, null, null, pin(target));
  assert.equal(await am.acquireAccount(null, 30, null, null, pin(target)), null);
  assert.equal(am.accounts[1].inFlight, 0);
  am.releaseAccount(first);
});

test('canonical acquire wakes a pinned request after its pause and respects abort', async () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    stormRamp: { startConc: 5, stepConc: 1, stepMs: 10, windowMs: 1000, pollMs: 5 },
    maxConcurrent: 5, queueTimeoutMs: 500,
  });
  const target = am.accounts[0];
  am.pauseAccount(target.index, 0.04);
  const account = await am.acquireAccount(null, 500, null, null, pin(target));
  assert.equal(account, target);
  am.releaseAccount(account);

  am.pauseAccount(target.index, 1);
  const controller = new AbortController();
  const pending = am.acquireAccount(null, 500, controller.signal, null, pin(target));
  controller.abort();
  assert.equal(await pending, null);
  assert.equal(target.inFlight, 0);
});

test('canonical acquire rejects unavailable, disabled, and auth-error pins without fallback', async () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98, { maxConcurrent: 2 });
  const target = am.accounts[0];
  target.status = 'exhausted';
  assert.equal(await am.acquireAccount(null, 0, null, null, pin(target)), null);
  target.status = 'active';
  target.disabled = true;
  assert.equal(await am.acquireAccount(null, 0, null, null, pin(target)), null);
  target.disabled = false;
  target.status = 'error';
  assert.equal(await am.acquireAccount(null, 0, null, null, pin(target)), null);
  assert.equal(am.accounts[1].inFlight, 0);
});
