import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const pin = account => ({ pinnedAccount: account });

test('null queue timeout waits for capacity and retains the bounded overflow depth', async () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    maxConcurrent: 1, maxQueueDepth: 1, queueTimeoutMs: null,
  });
  const first = await am.acquireAccount();
  const pending = am.acquireAccount();
  assert.equal(am._waiters.length, 1);
  assert.equal(am._waiters[0].timer, null, 'an indefinite wait must not arm a timeout');
  assert.equal(await am.acquireAccount(), null, 'indefinite waiting does not unbound the queue');
  am.releaseAccount(first);
  const second = await pending;
  assert.equal(second, first);
  am.releaseAccount(second);
});

test('provider contexts partition both canonical and positional acquisition', async () => {
  const am = new AccountManager([
    oauth('claude'),
    oauth('codex', { provider: 'codex', accountId: 'chatgpt-seat' }),
  ], 0.98, { maxConcurrent: 1 });
  const codex = am.accounts[1];
  const first = await am.acquireAccount(null, 0, null, null, { provider: 'codex' });
  assert.equal(first, codex);
  assert.equal(await am.acquireAccount(null, 0, null, null, { provider: 'codex' }), null);
  assert.equal(am.getActiveAccount(null, null, null, null, 'codex'), codex);
  assert.equal(am.accounts[0].inFlight, 0);
  am.releaseAccount(first);
});

test('an explicit finite priority beats auto and auto retains weekly use-or-lose', () => {
  const am = new AccountManager([oauth('soon'), oauth('later')], 0.98, { reevalIntervalMs: 0 });
  const now = Date.now();
  for (const [index, account] of am.accounts.entries()) {
    Object.assign(account.quota, {
      unified5h: 0.2, unified5hReset: now + 60_000,
      unified7d: 0.2, unified7dReset: now + (index + 1) * 3600_000,
    });
  }
  assert.equal(am._selectBest(), am.accounts[0]);
  assert.equal(am.setPriority(1, 50), null, 'positional indices are not stable control references');
  assert.equal(am.accounts[1].priority, null);
  am.setPriority(am.accounts[1], 50);
  assert.equal(am.getActiveAccount(), am.accounts[1]);
  am.setPriority(am.accounts[1], null);
  assert.equal(am.getActiveAccount(), am.accounts[0]);
  assert.equal(am.expiryRouting.enabled, false);
});

test('finite priority preempts both a new and an existing distributed session', () => {
  const am = new AccountManager([oauth('auto'), oauth('ranked', { priority: 100 })], 0.98, {
    distributeSessions: true,
  });
  am.recordSession('pinned', am.accounts[0], 'claude-sonnet-4-6');
  assert.equal(am.getActiveAccount(null, 'claude-sonnet-4-6', null, 'new'), am.accounts[1]);
  assert.equal(am.getActiveAccount(null, 'claude-sonnet-4-6', null, 'pinned'), am.accounts[1]);
});

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

test('_rampCap grows linearly during the window and lifts after it', () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    ramp: { startConc: 1, stepConc: 2, stepMs: 100, windowMs: 1000, pollMs: 5 },
  });
  const acct = am.accounts[0];

  assert.equal(am._rampCap(acct, 0), Infinity, 'no ramp until one starts');
  acct.rampStartedAt = 1000;
  assert.equal(am._rampCap(acct, 1000), 1, 'startConc at t=0');
  assert.equal(am._rampCap(acct, 1000 + 100), 3, '+stepConc after one step');
  assert.equal(am._rampCap(acct, 1000 + 250), 5, '+2*stepConc after two steps');
  assert.equal(am._rampCap(acct, 1000 + 1000), Infinity, 'unbounded past the window');
  assert.equal(acct.rampStartedAt, null, 'window expiry clears the ramp');
});

test('admit caps concurrency to a freshly-switched account; release frees a slot', async () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    ramp: { startConc: 1, stepConc: 1, stepMs: 10_000, windowMs: 60_000, pollMs: 5 },
  });
  am._beginRamp(am.accounts[0]); // cap pinned at 1 for the length of this test

  assert.equal(await am.admit(0), true);
  assert.equal(am.accounts[0].inFlight, 1);

  // A second request must wait — the cap is 1 and a slot is taken.
  let second = false;
  const p = am.admit(0).then(() => { second = true; });
  await sleep(30);
  assert.equal(second, false, 'second admit blocked by the ramp cap');

  am.release(0);       // free the slot
  await p;
  assert.equal(second, true, 'second admit proceeds once a slot frees');
  assert.equal(am.accounts[0].inFlight, 1);
});

test('admit is fail-open: aborts (returns false) if the client goes away while waiting', async () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    ramp: { startConc: 1, stepConc: 1, stepMs: 10_000, windowMs: 60_000, pollMs: 5 },
  });
  am._beginRamp(am.accounts[0]);
  await am.admit(0); // take the only slot

  let gone = false;
  const p = am.admit(0, () => gone); // waits: cap 1, inFlight 1
  await sleep(20);
  gone = true;                        // client disconnects
  assert.equal(await p, false, 'aborted admit returns false, takes no slot');
  assert.equal(am.accounts[0].inFlight, 1, 'no slot leaked to the aborted request');
});

test('ramp disabled → admit is immediate below the configured cap', async () => {
  const am = new AccountManager([oauth('a')], 0.98, { ramp: { enabled: false } });
  am._beginRamp(am.accounts[0]);
  assert.equal(am.accounts[0].rampStartedAt, null, 'no ramp window when disabled');
  assert.equal(await am.admit(0), true);
  assert.equal(await am.admit(0), true);
  assert.equal(am.accounts[0].inFlight, 2, 'configured cap still permits two slots');
});

test('switching to a new account begins a ramp on it', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98, { ramp: { enabled: true } });
  am.accounts[0].status = 'exhausted'; // force selection off the current (index 0)
  const next = am._selectNext();
  assert.equal(next.name, 'b');
  assert.ok(am.accounts[1].rampStartedAt != null, 'the switch armed a ramp on b');
});

test('release never drives inFlight negative', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.release(0);
  am.release(0);
  assert.equal(am.accounts[0].inFlight, 0);
});

test('pauseAccount pauses without throttling — account stays selectable (no rotation)', () => {
  const am = new AccountManager([oauth('a')], 0.98, { ramp: { pollMs: 5 } });
  am.pauseAccount(0, 30);
  const acct = am.accounts[0];
  assert.ok(acct.pausedUntil > Date.now(), 'pausedUntil set');
  assert.notEqual(acct.status, 'throttled', 'pause must not throttle');
  assert.equal(acct.rateLimitedUntil, null, 'pause is not a rate-limit hold');
  assert.equal(am._isAvailable(acct, 'claude-opus-4-6'), true, 'account stays available → selection never rotates away');
});

test('pauseAccount extends an existing pause, never shortens it', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.pauseAccount(0, 30);
  const long = am.accounts[0].pausedUntil;
  am.pauseAccount(0, 1); // shorter — must not shorten
  assert.equal(am.accounts[0].pausedUntil, long);
});

test('pauseAccount and markRateLimited ignore a non-finite or non-positive duration', async () => {
  const am = new AccountManager([oauth('a')], 0.98, { ramp: { startConc: 1, stepConc: 1, stepMs: 10, windowMs: 100, pollMs: 5 } });
  const acct = am.accounts[0];
  for (const bad of [NaN, Infinity, -Infinity, 0, -5, undefined, 'soon']) {
    am.pauseAccount(0, bad);
    am.markRateLimited(0, bad);
  }
  assert.equal(acct.pausedUntil, null);
  assert.equal(acct.rampStartedAt, null);
  assert.equal(acct.rateLimitedUntil, null);
  assert.equal(acct.status, 'active');
  assert.equal(am._rampCap(acct), Infinity);
  assert.equal(await am.admit(0), true, 'admit is not stuck');
  am.release(0);

  am.markRateLimited(0, 30);
  assert.equal(acct.status, 'throttled', 'a real duration still holds');
});

test('admit holds a request during a pause, then admits once it lifts', async () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    ramp: { startConc: 10, stepConc: 1, stepMs: 10, windowMs: 60_000, pollMs: 5 },
  });
  am.accounts[0].pausedUntil = Date.now() + 120; // ~120ms pause

  const start = Date.now();
  const admitted = await am.admit(0);
  const waited = Date.now() - start;

  assert.equal(admitted, true);
  assert.ok(waited >= 100, `admit should wait out the pause, waited ${waited}ms`);
  assert.equal(am.accounts[0].inFlight, 1);
});

test('admit aborts (returns false) if the client disconnects during a pause', async () => {
  const am = new AccountManager([oauth('a')], 0.98, { ramp: { pollMs: 5 } });
  am.accounts[0].pausedUntil = Date.now() + 10_000; // long pause
  let gone = false;
  const p = am.admit(0, () => gone);
  await sleep(20);
  gone = true;
  assert.equal(await p, false, 'aborted admit returns false');
  assert.equal(am.accounts[0].inFlight, 0, 'no slot taken');
});

test('pauseAccount arms the ramp at pause-end so held requests release staggered', () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    ramp: { startConc: 1, stepConc: 1, stepMs: 250, windowMs: 30_000, pollMs: 5 },
  });
  am.pauseAccount(0, 30);
  const acct = am.accounts[0];
  // Ramp is armed to begin exactly when the pause lifts.
  assert.equal(acct.rampStartedAt, acct.pausedUntil);
  // At the instant the pause lifts, the cap starts low (staggered release).
  assert.equal(am._rampCap(acct, acct.pausedUntil), 1);
  assert.equal(am._rampCap(acct, acct.pausedUntil + 250), 2);
});

test('addAccount initializes storm-control fields so a runtime-added account can admit/release', async () => {
  const am = new AccountManager([oauth('a')], 0.98, {
    ramp: { startConc: 1, stepConc: 1, stepMs: 10_000, windowMs: 60_000, pollMs: 5 },
  });
  const idx = am.addAccount(oauth('b'));
  const acct = am.accounts[idx];

  // Regression: addAccount once omitted inFlight/rampStartedAt/pausedUntil, so
  // `undefined < cap` in admit() was always false and every request routed to a
  // runtime-added account hung forever (and release() was a silent no-op).
  assert.equal(acct.inFlight, 0);
  assert.equal(acct.rampStartedAt, null);
  assert.equal(acct.pausedUntil, null);

  assert.equal(await am.admit(idx), true, 'a fresh added account admits immediately (no ramp started yet)');
  assert.equal(acct.inFlight, 1);
  am.release(idx);
  assert.equal(acct.inFlight, 0, 'release frees the slot on a runtime-added account');
});
