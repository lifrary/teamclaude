import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';
import { Prober } from '../src/prober.js';

// 2026-09-29 23:03 KST, live: one account's quota probe never settled. Its
// maintenance lane kept the account's slot and blocked its warm-ups, and the run
// it belonged to never finished, so probeAll kept handing back that same run and
// no account was probed again for eleven hours. Each read inside a probe is
// bounded; what was not bounded is the probe as a whole, nor the run's wait for
// an account whose lane some other maintenance holds.

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, expiresAt: Date.now() + 3600_000, ...extra };
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const reading = () => ({ sevenDay: { utilization: 0.3, resetAt: Date.now() + 86400_000 } });

/** The run's outcome, or 'hung' when it has not finished within `ms`. The
 * ceiling timer stays ref'd, since the prober's own timers are not and would
 * let node:test cancel the test, and is cleared once the race is decided. */
function finishes(promise, ms = 2_000) {
  let timer;
  const ceiling = new Promise(resolve => { timer = setTimeout(resolve, ms, 'hung'); });
  return Promise.race([promise.then(() => 'finished'), ceiling]).finally(() => clearTimeout(timer));
}

test('a probe that never settles, even when aborted, cannot freeze the prober', async () => {
  const am = new AccountManager([oauth('stuck'), oauth('fine')], 0.98);
  const calls = { stuck: 0, fine: 0 };
  // The stuck read ignores its abort signal, so _withTimeout waits on it forever.
  const probeFn = async credential => {
    if (credential === 't-stuck') { calls.stuck++; return new Promise(() => {}); }
    calls.fine++;
    return reading();
  };
  const lines = [];
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: line => lines.push(line), ownCoordinator: true });

  assert.equal(await finishes(prober.probeAll()), 'finished', 'the run ends although one read never does');
  assert.equal(am.accounts[0].inflight, 0, 'the stuck account gets its slot back');
  const first = prober.getStatus();
  assert.equal(first.running, false);
  assert.equal(first.accounts[0].status, 'timeout');
  assert.match(first.accounts[0].error, /abandoned after .* usage read/);
  assert.equal(first.accounts[1].status, 'ok');
  assert.equal(lines.filter(line => line.includes('abandoned')).length, 1);

  // The next run probes the healthy account again and stacks no second read on
  // the one whose first read is still out.
  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.deepEqual(calls, { stuck: 1, fine: 2 });
  const second = prober.getStatus().accounts[0];
  assert.equal(second.status, 'stalled', 'the skip is visible, not an old result left to age');
  assert.match(second.error, /abandoned at .* has not come back/);
  prober.stop();
});

test('a token refresh that never settles is abandoned too, and names its phase', async () => {
  // Outside _withTimeout: the refresh that runs before the read.
  const am = new AccountManager([oauth('expired', { refreshToken: 'r', expiresAt: Date.now() - 1_000 })], 0.98, {
    refreshFn: () => new Promise(() => {}),
  });
  let reads = 0;
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn: async () => { reads++; return reading(); },
    log: () => {}, ownCoordinator: true });

  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(am.accounts[0].inflight, 0);
  assert.match(prober.getStatus().accounts[0].error, /abandoned after .* token refresh/);
  assert.equal(reads, 0);
  prober.stop();
});

test('a probe cancelled by shutdown whose read ignores the cancel ends cancelled, silently', async () => {
  const am = new AccountManager([oauth('stuck')], 0.98);
  let markStarted;
  const started = new Promise(resolve => { markStarted = resolve; });
  const probeFn = () => { markStarted(); return new Promise(() => {}); };
  const lines = [];
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: line => lines.push(line), ownCoordinator: true });

  const run = prober.probeAll();
  await started;
  prober.stop();
  assert.equal(await finishes(run), 'finished');
  assert.equal(prober.getStatus().accounts[0].status, 'cancelled');
  assert.equal(lines.filter(line => line.includes('abandoned')).length, 0);
});

test('an abandoned probe that settles late lets the account be probed again', async () => {
  const am = new AccountManager([oauth('slow')], 0.98);
  let release;
  let calls = 0;
  const probeFn = async () => {
    calls++;
    if (calls === 1) return new Promise(resolve => { release = () => resolve(reading()); });
    return reading();
  };
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: () => {}, ownCoordinator: true });

  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(prober.getStatus().accounts[0].status, 'timeout');
  release();
  await sleep(10);
  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(calls, 2, 'once the first read came back, the account is read again');
  assert.equal(prober.getStatus().accounts[0].status, 'ok');
  prober.stop();
});

test('an account whose maintenance lane other work holds cannot freeze the run', async () => {
  const am = new AccountManager([oauth('busy'), oauth('fine')], 0.98);
  let calls = 0;
  const probeFn = async () => { calls++; return reading(); };
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: () => {}, ownCoordinator: true });
  // Another kind of maintenance that never finishes holds the busy account's lane,
  // so its probe job waits behind it.
  prober.coordinator.run(am.accounts[0], 'warmup', 10, () => new Promise(() => {}));

  assert.equal(await finishes(prober.probeAll()), 'finished', 'the run ends although one lane never frees');
  assert.equal(calls, 1, 'the free account was probed');
  assert.equal(prober.getStatus().running, false);
  assert.equal(await finishes(prober.probeAll()), 'finished', 'and the next run ends too');
  prober.stop();
});
