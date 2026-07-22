import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';
import { MaintenanceCoordinator } from '../src/maintenance-coordinator.js';
import { Prober } from '../src/prober.js';
import { Warmer } from '../src/warmer.js';
import { accountIdKey } from '../src/identity.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

// A fake spawner: records each spawn spec and resolves like a clean `claude` run
// (exit 0). Lets us assert the warmer's behavior without launching anything.
function fakeSpawner(result = 0) {
  const calls = [];
  const fn = async (spec) => {
    calls.push(spec);
    if (result instanceof Error) throw result;
    return result;
  };
  fn.calls = calls;
  return fn;
}

function makeWarmer(am, spawnFn, opts = {}) {
  return new Warmer(am, { intervalMs: 0, port: 3456, apiKey: 'tc-key', spawnFn, log: () => {}, ownCoordinator: true, ...opts });
}

// ── eligibility ──────────────────────────────────────────────────────────────

test('warms only healthy, idle Anthropic OAuth accounts with no live 5h window', async () => {
  const am = new AccountManager([
    oauth('idle'),                                   // ✓ target
    oauth('active'),                                 // ✗ 5h window already running
    oauth('third-party', { upstream: 'https://api.deepseek.com/anthropic' }), // ✗ not Anthropic
    oauth('disabled', { disabled: true }),           // ✗ disabled
    oauth('throttled'),                              // ✗ throttled
  ], 0.98);
  am.accounts[1].quota.unified5hReset = Date.now() + 3600_000; // 'active' has a live window
  am.accounts[4].status = 'throttled';

  const spawn = fakeSpawner();
  await makeWarmer(am, spawn).warmAll();

  assert.equal(spawn.calls.length, 1, 'exactly one account warmed');
  assert.equal(spawn.calls[0].env.ANTHROPIC_BASE_URL, `http://127.0.0.1:3456/tc-acct/${encodeURIComponent(accountIdKey(am.accounts[0]))}`);
});

test('an expired 5h window is a warm target again (keeps the timer going)', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.accounts[0].quota.unified5hReset = Date.now() - 1000; // window already reset
  const spawn = fakeSpawner();
  await makeWarmer(am, spawn).warmAll();
  assert.equal(spawn.calls.length, 1);
});

test('errored and exhausted accounts are skipped', async () => {
  const am = new AccountManager([oauth('err'), oauth('spent')], 0.98);
  am.accounts[0].status = 'error';
  am.accounts[1].status = 'exhausted';
  const spawn = fakeSpawner();
  await makeWarmer(am, spawn).warmAll();
  assert.equal(spawn.calls.length, 0);
});

// ── spawn spec ───────────────────────────────────────────────────────────────

test('the spawn invocation is a minimal non-interactive claude pinned to the account', async () => {
  const am = new AccountManager([oauth('solo', { accountUuid: 'person-1', orgName: 'R&D / Europe' })], 0.98);
  const spawn = fakeSpawner();
  await makeWarmer(am, spawn, { port: 9999, apiKey: 'tc-secret', model: 'haiku' }).warmAll();

  const spec = spawn.calls[0];
  assert.equal(spec.command, 'claude');
  assert.deepEqual(spec.args, ['-p', '--bare', '--model', 'haiku', '--output-format', 'text', 'hi']);
  assert.equal(spec.env.ANTHROPIC_BASE_URL, `http://127.0.0.1:9999/tc-acct/${encodeURIComponent(accountIdKey(am.accounts[0]))}`);
  assert.equal(spec.env.ANTHROPIC_API_KEY, 'tc-secret');
});

// ── status ───────────────────────────────────────────────────────────────────

test('status reflects a successful warm and marks third-party accounts not-applicable', async () => {
  const am = new AccountManager([
    oauth('idle'),
    oauth('ds', { upstream: 'https://api.deepseek.com/anthropic' }),
  ], 0.98);
  const warmer = makeWarmer(am, fakeSpawner());
  await warmer.warmAll();

  const st = warmer.getStatus();
  const idle = st.accounts.find(a => a.name === 'idle');
  const ds = st.accounts.find(a => a.name === 'ds');
  assert.equal(idle.status, 'ok');
  assert.ok(idle.lastWarmedAt);
  assert.equal(ds.status, 'not-applicable');
});

test('a non-zero exit is recorded as an error', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const warmer = makeWarmer(am, fakeSpawner(1));
  await warmer.warmAll();
  const st = warmer.getStatus().accounts.find(a => a.name === 'a');
  assert.equal(st.status, 'error');
  assert.match(st.error, /exited 1/);
});

test('a spawn failure (e.g. claude not on PATH) is recorded as an error, not thrown', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const warmer = makeWarmer(am, fakeSpawner(new Error('spawn claude ENOENT')));
  await warmer.warmAll(); // must not reject
  const st = warmer.getStatus().accounts.find(a => a.name === 'a');
  assert.equal(st.status, 'error');
  assert.match(st.error, /ENOENT/);
});

// ── scheduling ───────────────────────────────────────────────────────────────

test('getStatus reports enabled/interval and reschedule(0) turns it off', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const warmer = makeWarmer(am, fakeSpawner(), { intervalMs: 600_000 });
  assert.equal(warmer.getStatus().enabled, true);
  assert.equal(warmer.getStatus().intervalSeconds, 600);
  warmer.reschedule(0);
  assert.equal(warmer.getStatus().enabled, false);
  assert.equal(warmer.coordinator.timers.has(warmer.scheduleName), false);
});
test('unscheduling an immediate schedule prevents its queued callback from running', async () => {
  const coordinator = new MaintenanceCoordinator(new AccountManager([], 0.98), { log: () => {} });
  let calls = 0;

  coordinator.schedule('immediate', 60_000, () => { calls += 1; }, { immediate: true });
  coordinator.unschedule('immediate');
  await new Promise(resolve => setTimeout(resolve, 0));

  assert.equal(calls, 0);
  coordinator.shutdown();
});

test('a slow scheduled callback is coalesced into at most one follow-up', async () => {
  const coordinator = new MaintenanceCoordinator(new AccountManager([], 0.98), { log: () => {} });
  let starts = 0;
  let running = 0;
  let maxRunning = 0;
  let releaseFirst;
  let markFirstStarted;
  const firstStarted = new Promise(resolve => { markFirstStarted = resolve; });
  let markSecondStarted;
  const secondStarted = new Promise(resolve => { markSecondStarted = resolve; });

  coordinator.schedule('slow', 1, async () => {
    starts += 1;
    running += 1;
    maxRunning = Math.max(maxRunning, running);
    if (starts === 1) {
      markFirstStarted();
      await new Promise(resolve => { releaseFirst = resolve; });
    } else {
      markSecondStarted();
    }
    running -= 1;
  }, { immediate: true });
  await firstStarted;
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(starts, 1);
  assert.equal(maxRunning, 1);

  releaseFirst();
  await secondStarted;
  coordinator.unschedule('slow');
  await new Promise(resolve => setTimeout(resolve, 0));

  assert.equal(starts, 2);
  assert.equal(maxRunning, 1);
  coordinator.shutdown();
});

test('overlapping warm cycles are skipped while one is running', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const warmer = makeWarmer(am, fakeSpawner());
  warmer._runPromise = Promise.resolve();     // pretend a cycle is in flight
  await warmer.warmAll();              // must be a no-op
  assert.equal(warmer.lastRunStartedAt, null);
});

test('stop() aborts an in-flight sweep (kills the warm child, skips the rest)', async () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  let aborts = 0;
  let started = 0;
  // A spawner that hangs until its abort signal fires (models a live `claude`).
  const spawnFn = (spec) => new Promise((_resolve, reject) => {
    started += 1;
    spec.signal.addEventListener('abort', () => { aborts += 1; reject(new Error('aborted')); }, { once: true });
  });
  const warmer = makeWarmer(am, spawnFn);

  const sweep = warmer.warmAll();          // don't await — it's mid-flight
  await new Promise(r => setTimeout(r, 10));
  warmer.coordinator.shutdown();              // process shutdown aborts the hanging child
  await sweep;

  assert.equal(aborts, 1, 'the in-flight child was aborted');
  assert.equal(started, 1, 'the second account was not started after shutdown');
  assert.equal(warmer.getStatus().accounts[0].status, 'cancelled');
});

test('reschedule to a new interval does NOT trigger an extra (quota-spending) sweep', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const spawn = fakeSpawner();
  const warmer = makeWarmer(am, spawn, { intervalMs: 600_000 });
  warmer.start();                          // off→on: one immediate sweep
  await new Promise(r => setTimeout(r, 5));
  const afterStart = spawn.calls.length;
  warmer.reschedule(300_000);              // interval CHANGE, already on
  await new Promise(r => setTimeout(r, 5));
  assert.equal(spawn.calls.length, afterStart, 'no extra sweep on an interval change');
});
test('a warm-up timeout is recorded separately from an account error', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const warmer = makeWarmer(am, fakeSpawner(new Error('warm-up timed out after 5ms')));

  await warmer.warmAll();

  const status = warmer.getStatus().accounts[0];
  assert.equal(status.status, 'timeout');
  assert.match(status.error, /timed out/);
});
test('a shared coordinator serializes probe and warm-up for one account without exceeding capacity', async () => {
  const am = new AccountManager([oauth('a')], 0.98, { maxConcurrent: 1 });
  const coordinator = new MaintenanceCoordinator(am, { log: () => {} });
  let releaseProbe;
  const probeStarted = new Promise(resolve => {
    releaseProbe = resolve;
  });
  const prober = new Prober(am, {
    coordinator,
    probeFn: async () => {
      await probeStarted;
      return { sevenDay: { utilization: 0.2, resetAt: 5_000 } };
    },
    log: () => {},
  });
  const spawn = fakeSpawner();
  const warmer = makeWarmer(am, spawn, { coordinator });

  const probing = prober.probeAll();
  await new Promise(resolve => setTimeout(resolve, 0));
  const warming = warmer.warmAll();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(am.accounts[0].inflight, 1, 'normal admission cap is shared with maintenance');
  assert.equal(spawn.calls.length, 0, 'warm-up waits behind the probe for the same account');

  releaseProbe();
  await Promise.all([probing, warming]);
  assert.equal(spawn.calls.length, 1);
  assert.equal(am.accounts[0].inflight, 0);
  coordinator.shutdown();
});
test('same-kind maintenance calls share the running promise', async () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const coordinator = new MaintenanceCoordinator(am, { log: () => {} });
  let runs = 0;
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  const first = coordinator.run(am.accounts[0], 'quota-probe', 30, async () => {
    runs += 1;
    await waiting;
    return true;
  });
  await new Promise(resolve => setTimeout(resolve, 0));
  const second = coordinator.run(am.accounts[0], 'quota-probe', 30, () => {
    runs += 1;
    return true;
  });

  assert.strictEqual(second, first);
  release();
  assert.equal(await first, true);
  assert.equal(runs, 1);
  coordinator.shutdown();
});

test('a timed-out probe aborts its child and holds capacity until it settles', async () => {
  const am = new AccountManager([oauth('a')], 0.98, { maxConcurrent: 1 });
  const coordinator = new MaintenanceCoordinator(am, { log: () => {} });
  let aborted = false;
  let settle;
  const prober = new Prober(am, {
    coordinator,
    timeoutMs: 5,
    probeFn: (_credential, signal) => new Promise(resolve => {
      settle = resolve;
      signal.addEventListener('abort', () => { aborted = true; }, { once: true });
    }),
    log: () => {},
  });

  const probing = prober.probeAll();
  await new Promise(resolve => setTimeout(resolve, 15));
  assert.equal(aborted, true, 'timeout aborts the underlying probe');
  assert.equal(am.accounts[0].inflight, 1, 'admission remains held until the aborted probe settles');
  settle(null);
  await probing;
  assert.equal(am.accounts[0].inflight, 0);
  assert.equal(prober.getStatus().accounts[0].status, 'timeout');
  coordinator.shutdown();
});

test('standalone adapters must opt into ownership and stop shuts down only their coordinator', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  assert.throws(() => new Prober(am), /requires a MaintenanceCoordinator/);
  assert.throws(() => new Warmer(am, { port: 3456 }), /requires a MaintenanceCoordinator/);

  const prober = new Prober(am, { ownCoordinator: true, log: () => {} });
  prober.stop();
  assert.equal(prober.coordinator.closed, true);

  const warmer = new Warmer(am, { port: 3456, ownCoordinator: true, log: () => {} });
  warmer.stop();
  assert.equal(warmer.coordinator.closed, true);
  const shared = new MaintenanceCoordinator(am, { log: () => {} });
  new Prober(am, { coordinator: shared, log: () => {} }).stop();
  new Warmer(am, { port: 3456, coordinator: shared, log: () => {} }).stop();
  assert.equal(shared.closed, false);
  shared.shutdown();
});
