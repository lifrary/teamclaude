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

// The wait before an account whose probe was abandoned is tried again runs on
// the prober's injected clock, so these tests decide when it has passed rather
// than racing real time on a loaded machine. With timeoutMs 10 the deadline is
// 120 ms and the wait is five deadlines.
const RETRY_WAIT_MS = 10 * 12 * 5;
function clock(start = Date.now()) {
  let t = start;
  const now = () => t;
  now.advance = (/** @type {number} */ ms) => { t += ms; };
  return now;
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
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: line => lines.push(line), ownCoordinator: true, now: clock() });

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

// 2026-10-06, live: the reads of all ten accounts hung past their abort and never
// came back. Each account waited for its stuck read before sending another, so
// none was probed for 33 hours, although fresh reads worked at once.

test('a probe that never comes back is tried again after a wait, so one hung read cannot blind the account for good', async () => {
  const am = new AccountManager([oauth('hung')], 0.98);
  let calls = 0;
  const probeFn = async () => { calls++; return calls === 1 ? new Promise(() => {}) : reading(); };
  const now = clock();
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: () => {}, ownCoordinator: true, now });

  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(prober.getStatus().accounts[0].status, 'timeout');
  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(calls, 1, 'not straight away');
  assert.match(prober.getStatus().accounts[0].error, /has not come back; next try after/);
  now.advance(RETRY_WAIT_MS);
  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(calls, 2, 'but after the wait, although the first read is still out');
  assert.equal(prober.getStatus().accounts[0].status, 'ok');
  prober.stop();
});

test('three probes abandoned in a row, all still out, skip the account', async () => {
  const am = new AccountManager([oauth('dead')], 0.98);
  let calls = 0;
  const probeFn = () => { calls++; return new Promise(() => {}); };
  const now = clock();
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: () => {}, ownCoordinator: true, now });

  for (let i = 0; i < 3; i++) {
    assert.equal(await finishes(prober.probeAll()), 'finished');
    now.advance(RETRY_WAIT_MS);
  }
  assert.equal(calls, 3);
  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(calls, 3, 'no fourth read while three are out');
  const status = prober.getStatus().accounts[0];
  assert.equal(status.status, 'stalled');
  assert.match(status.error, /3 probes in a row were abandoned since .* and have not come back/);
  prober.stop();
});

test('reads that never came back stop counting once a later probe settles in time', async () => {
  // A review found the count spanning the account's whole life: three hangs days
  // apart, with healthy probes between them, skipped it until a restart.
  const am = new AccountManager([oauth('flaky')], 0.98);
  let calls = 0;
  const probeFn = () => { calls++; return calls % 2 === 1 ? new Promise(() => {}) : Promise.resolve(reading()); };
  const now = clock();
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: () => {}, ownCoordinator: true, now });

  for (let run = 0; run < 6; run++) {
    assert.equal(await finishes(prober.probeAll()), 'finished');
    now.advance(RETRY_WAIT_MS);
  }
  assert.equal(calls, 6, 'three hangs, each followed by a probe that settled');
  assert.equal(prober.getStatus().accounts[0].status, 'ok');
  prober.stop();
});

test('an abandoned probe that comes back after a newer one cannot overwrite its record', async () => {
  const am = new AccountManager([oauth('late')], 0.98);
  let release;
  let calls = 0;
  const probeFn = async () => {
    calls++;
    if (calls === 1) return new Promise(resolve => { release = () => resolve(reading()); });
    return reading();
  };
  const now = clock();
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: () => {}, ownCoordinator: true, now });

  assert.equal(await finishes(prober.probeAll()), 'finished');
  now.advance(RETRY_WAIT_MS);
  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(prober.getStatus().accounts[0].status, 'ok');
  release();
  await sleep(10);
  assert.equal(prober.getStatus().accounts[0].status, 'ok', 'the first probe came back late and was ignored');
  prober.stop();
});

test('a probe that comes back while a newer one is out stops counting against the account', async () => {
  const am = new AccountManager([oauth('mixed')], 0.98);
  let release;
  let calls = 0;
  const probeFn = () => {
    calls++;
    if (calls === 1) return new Promise(resolve => { release = () => resolve(reading()); });
    // The first read comes back while the second is out; the second never does.
    if (calls === 2) { setTimeout(() => release(), 20); return new Promise(() => {}); }
    if (calls === 3) return new Promise(() => {});
    return Promise.resolve(reading());
  };
  const now = clock();
  const prober = new Prober(am, { intervalMs: 0, timeoutMs: 10, probeFn, log: () => {}, ownCoordinator: true, now });

  for (let i = 0; i < 3; i++) {
    assert.equal(await finishes(prober.probeAll()), 'finished');
    now.advance(RETRY_WAIT_MS);
  }
  assert.equal(await finishes(prober.probeAll()), 'finished');
  assert.equal(calls, 4, 'two reads are out, not three');
  assert.equal(prober.getStatus().accounts[0].status, 'ok');
  prober.stop();
});
