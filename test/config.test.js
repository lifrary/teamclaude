import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, mkdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  atomicConfigUpdate,
  clearServerState,
  formatServerStateFailure,
  getQuotaCachePath,
  getServerStatePath,
  readQuotaCache,
  readServerState,
  writeServerState,
  saveConfig,
  createCanonicalState,
  createRekeyRecord,
  loadCanonicalState,
  migrateLegacyState,
  reconcilePendingRekey,
  reconcileRekeyRecord,
  saveCanonicalState,
  statePayloadDigest,
  loadConfig,
  normalizeConfig,
} from '../src/config.js';

// node --test runs each test file in its own process, so setting TEAMCLAUDE_CONFIG
// (and the module-level write chain) here doesn't leak into other test files.

test('atomicConfigUpdate serializes concurrent writers (no lost update / no resurrection)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-cfg-'));
  const cfgPath = join(dir, 'teamclaude.json');
  const prev = process.env.TEAMCLAUDE_CONFIG;
  process.env.TEAMCLAUDE_CONFIG = cfgPath;
  try {
    await writeFile(cfgPath, JSON.stringify({
      proxy: { port: 1 },
      accounts: [
        { name: 'A', type: 'apikey', apiKey: 'a' },
        { name: 'B', type: 'apikey', apiKey: 'b' },
      ],
    }, null, 2) + '\n', { mode: 0o600 });

    // Two concurrent read-modify-write cycles: one DELETES A (like a TUI delete),
    // the other UPDATES B's token (like a background token refresh). Each reads the
    // whole file and writes it all back — without serialization the later write
    // clobbers the earlier (either resurrecting A or losing B's update).
    await Promise.all([
      atomicConfigUpdate(c => { c.accounts = c.accounts.filter(a => a.name !== 'A'); }),
      atomicConfigUpdate(c => { const b = c.accounts.find(a => a.name === 'B'); if (b) b.apiKey = 'b-new'; }),
    ]);

    const final = JSON.parse(await readFile(cfgPath, 'utf8'));
    assert.deepEqual(final.accounts.map(a => a.name), ['B'], 'A stays deleted (not resurrected)');
    assert.equal(final.accounts[0].apiKey, 'b-new', "B's concurrent update is not lost");
  } finally {
    if (prev === undefined) delete process.env.TEAMCLAUDE_CONFIG;
    else process.env.TEAMCLAUDE_CONFIG = prev;
    await rm(dir, { recursive: true, force: true });
  }
});
test('state and legacy quota-cache reads handle missing and failed storage without leaking paths', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-cfg-secret-'));
  const cfgPath = join(dir, 'credential-should-not-appear.json');
  const prev = process.env.TEAMCLAUDE_CONFIG;
  const warnings = [];
  const originalWarn = console.warn;
  process.env.TEAMCLAUDE_CONFIG = cfgPath;
  console.warn = (...args) => warnings.push(args.join(' '));

  try {
    assert.equal(await readServerState(), null);
    assert.equal(await readQuotaCache(), null);
    assert.deepEqual(warnings, [], 'missing files are expected and quiet');

    await writeFile(getServerStatePath(), '{not json', { mode: 0o600 });
    assert.equal(await readServerState(), null);

    await rm(getServerStatePath());
    await mkdir(getServerStatePath());
    assert.equal(await readServerState(), null, 'filesystem failures are not treated as missing');

    await writeFile(getQuotaCachePath(), '{not json', { mode: 0o600 });
    assert.equal(await readQuotaCache(), null);

    await rm(getQuotaCachePath());
    await mkdir(getQuotaCachePath());
    assert.equal(await readQuotaCache(), null, 'cache filesystem failures are reported');
  } finally {
    console.warn = originalWarn;
    if (prev === undefined) delete process.env.TEAMCLAUDE_CONFIG;
    else process.env.TEAMCLAUDE_CONFIG = prev;
    await rm(dir, { recursive: true, force: true });
  }

  assert.equal(warnings.length, 4);
  assert.ok(warnings.some(warning => warning.includes('invalid JSON')));
  assert.ok(warnings.some(warning => warning.includes('filesystem error (EISDIR)')));
  assert.ok(warnings.every(warning => !warning.includes(cfgPath)));
  assert.ok(warnings.every(warning => !warning.includes('credential-should-not-appear')));
});

test('shipped config example parses and has unique priority fields', async () => {
  const example = await readFile(new URL('../config.example.json', import.meta.url), 'utf8');
  const config = JSON.parse(example);

  assert.equal(config.proxy.port, 3456);
  assert.equal(config.quotaProbeSeconds, 0);
  assert.equal(config.accounts[1].priority, 2);
  assert.equal(config.accounts[1].maxConcurrent, 5);
  assert.equal(config.accounts[2].disabled, false);
  assert.deepEqual(config.routes[0].accounts, ['primary-max']);
  assert.equal(config.sx.mode, '429');

  const priorityEntries = example.match(/"priority"\s*:/g) || [];
  const prioritizedAccounts = config.accounts.filter(account =>
    Object.prototype.hasOwnProperty.call(account, 'priority'));
  assert.equal(priorityEntries.length, prioritizedAccounts.length);
});
test('sx config accepts only canonical modes and normalizes the legacy mode key', async () => {
  for (const mode of ['off', '429', 'always']) {
    assert.equal(normalizeConfig({ sx: { apiKey: 'key', mode } }).sx.mode, mode);
  }

  const normalized = normalizeConfig({ sxMode: '429' });
  assert.deepEqual(normalized, { sx: { mode: '429' } });
  assert.equal(Object.hasOwn(normalized, 'sxMode'), false);

  for (const mode of ['on', '', 429, null, {}]) {
    assert.throws(() => normalizeConfig({ sx: { mode } }), /Config sx\.mode/);
  }
  assert.throws(
    () => normalizeConfig({ sx: { mode: 'off' }, sxMode: 'off' }),
    /both sx and legacy sxMode/,
  );
  assert.throws(
    () => normalizeConfig({ sx: { apiKey: 'key' }, sxMode: 'off' }),
    /both sx and legacy sxMode/,
  );
  assert.throws(
    () => normalizeConfig({ sx: { apiKey: 'key' } }),
    /sx\.mode is required/,
  );

  const dir = await mkdtemp(join(tmpdir(), 'tc-sx-config-'));
  const cfgPath = join(dir, 'teamclaude.json');
  const prev = process.env.TEAMCLAUDE_CONFIG;
  process.env.TEAMCLAUDE_CONFIG = cfgPath;
  try {
    await writeFile(cfgPath, JSON.stringify({ sxMode: 'off' }));
    assert.deepEqual(await loadConfig(), { sx: { mode: 'off' } });

    let fsCalled = false;
    assert.throws(
      () => saveConfig({ sx: { mode: 'invalid' } }, {
        path: cfgPath,
        fs: {
          mkdir: async () => { fsCalled = true; },
          open: async () => { fsCalled = true; },
          rename: async () => { fsCalled = true; },
          rm: async () => { fsCalled = true; },
          chmod: async () => { fsCalled = true; },
        },
      }),
      /Config sx\.mode/,
    );
    assert.equal(fsCalled, false, 'invalid mode fails before config write side effects');
  } finally {
    if (prev === undefined) delete process.env.TEAMCLAUDE_CONFIG;
    else process.env.TEAMCLAUDE_CONFIG = prev;
    await rm(dir, { recursive: true, force: true });
  }
});

test('saveConfig persists canonical sx.mode and never the legacy key', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-sx-save-'));
  const path = join(dir, 'teamclaude.json');
  try {
    await saveConfig({ sxMode: 'off' }, { path });
    assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), { sx: { mode: 'off' } });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test('server state write, chmod, and clear failures are sanitized and fail-safe', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-state-'));
  const path = join(dir, 'private.server.json');
  const secretPath = '/private/credentials/very-secret.server.json';
  const failure = code => Object.assign(new Error(secretPath), { code });

  try {
    await writeServerState({ pid: 1, port: 3456 }, { path });
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    await clearServerState({ path });

    for (const [operation, fs, code] of [
      ['write', { mkdir: async () => {}, writeFile: async () => { throw failure('EACCES'); }, chmod: async () => {} }, 'EACCES'],
      ['chmod', { mkdir: async () => {}, writeFile: async () => {}, chmod: async () => { throw failure('EPERM'); } }, 'EPERM'],
    ]) {
      await assert.rejects(
        writeServerState({ pid: 1 }, { path: secretPath, fs }),
        error => {
          assert.equal(error.operation, operation);
          const diagnostic = formatServerStateFailure(error);
          assert.match(diagnostic, new RegExp(`${operation} failed \\(${code}\\)`));
          assert.doesNotMatch(diagnostic, /private|secret/);
          return true;
        },
      );
    }

    await assert.rejects(
      clearServerState({ path: secretPath, fs: { rm: async () => { throw failure('EACCES'); } } }),
      error => {
        assert.equal(error.operation, 'clear');
        const diagnostic = formatServerStateFailure(error);
        assert.match(diagnostic, /clear failed \(EACCES\)/);
        assert.doesNotMatch(diagnostic, /private|secret/);
        return true;
      },
    );
    await clearServerState({ path: secretPath, fs: { rm: async () => { throw failure('ENOENT'); } } });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test('saveConfig fails closed when credential permission enforcement fails', async () => {
  const secretPath = '/private/credentials/teamclaude.json';
  const credential = 'secret-access-token';
  const failure = Object.assign(new Error(secretPath), { code: 'EPERM' });
  const calls = [];

  await assert.rejects(
    saveConfig(
      { accounts: [{ accessToken: credential }] },
      {
        path: secretPath,
        fs: {
          mkdir: async () => {},
          open: async () => {
            calls.push('open');
            return {
              writeFile: async () => calls.push('write'),
              sync: async () => calls.push('sync'),
              close: async () => calls.push('close'),
            };
          },
          chmod: async () => { calls.push('chmod'); throw failure; },
          rename: async () => calls.push('rename'),
          rm: async () => calls.push('rm'),
        },
      },
    ),
    error => {
      assert.equal(error.operation, 'write');
      assert.equal(error.errorClass, 'EPERM');
      assert.equal(error.message, 'Config write failed');
      assert.doesNotMatch(error.message, /private|secret|credentials/);
      return true;
    },
  );
  assert.deepEqual(calls, ['open', 'chmod', 'close', 'rm']);

  assert.equal(calls.includes('write'), false);
});
test('canonical v2 state is atomic, mode 0600, and suppresses legacy import when invalid', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-v2-'));
  const path = join(dir, 'teamclaude.state.v2.json');
  const legacyPath = join(dir, 'teamclaude.state.json');
  const accounts = { 'u:p1:o:o1': { quota: { unified5h: 0.5 } } };
  const state = createCanonicalState({
    accounts,
    activeAccountId: 'u:p1:o:o1',
    migration: { completed: true, sourceDigests: {} },
  });
  try {
    await saveCanonicalState(state, { path });
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.deepEqual(await loadCanonicalState({ path, legacyPath }), state);

    await writeFile(legacyPath, JSON.stringify([{ name: 'legacy', quota: {} }]));
    await writeFile(path, '{invalid');
    await assert.rejects(loadCanonicalState({ path, legacyPath }), /Canonical state parse failed/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rekey records contain only digest-bound identity and state evidence', () => {
  const source = { type: 'oauth', accountUuid: 'p1', orgName: 'Acme', accessToken: 'secret' };
  const target = { type: 'oauth', accountUuid: 'p1', orgUuid: 'o1', refreshToken: 'secret' };
  const before = createCanonicalState({
    accounts: { 'u:p1:n:acme': { quota: { unified5h: 0.1 } } },
    activeAccountId: 'u:p1:n:acme',
  });
  const after = createCanonicalState({
    ...before,
    accounts: { 'u:p1:o:o1': before.accounts['u:p1:n:acme'] },
    activeAccountId: 'u:p1:o:o1',
  });
  const record = createRekeyRecord({ from: source, to: target, beforeState: before, afterState: after });
  assert.deepEqual(Object.keys(record).sort(), [
    'newAccountIdDigest', 'newConfigIdentityDigest', 'newStateDigest', 'newTupleDigest',
    'oldAccountIdDigest', 'oldConfigIdentityDigest', 'oldStateDigest', 'oldTupleDigest', 'phase',
  ]);
  assert.equal(record.oldStateDigest, statePayloadDigest(before));
  assert.doesNotMatch(JSON.stringify(record), /Acme|p1|o1|secret/);
  assert.throws(
    () => reconcileRekeyRecord({ ...record, oldStateDigest: '0'.repeat(64) }, before, [source]),
    /Canonical state rekey payload failed/,
  );
});

test('startup rekey reconciliation follows durable phase authority and clears records', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-rekey-'));
  const statePath = join(dir, 'state.json');
  const rekeyPath = join(dir, 'state.json.rekey');
  const source = { type: 'oauth', accountUuid: 'p1', orgName: 'Acme' };
  const target = { type: 'oauth', accountUuid: 'p1', orgUuid: 'o1' };
  const before = createCanonicalState({
    accounts: { 'u:p1:n:acme': { quota: { unified5h: 0.1 } } },
    activeAccountId: 'u:p1:n:acme',
  });
  const after = createCanonicalState({
    ...before,
    accounts: { 'u:p1:o:o1': before.accounts['u:p1:n:acme'] },
    activeAccountId: 'u:p1:o:o1',
  });
  const prepared = createRekeyRecord({ from: source, to: target, beforeState: before, afterState: after });

  try {
    await writeFile(rekeyPath, JSON.stringify(prepared));
    assert.deepEqual(
      await reconcilePendingRekey({ state: before, authoritativeAccounts: [source], statePath, rekeyPath }),
      before,
      'prepared restores old state',
    );
    await assert.rejects(readFile(rekeyPath), { code: 'ENOENT' });
    await writeFile(rekeyPath, JSON.stringify(prepared));
    assert.deepEqual(
      await reconcilePendingRekey({ state: before, authoritativeAccounts: [target], statePath, rekeyPath }),
      after,
      'config rename before phase still completes new state',
    );
    await assert.rejects(readFile(rekeyPath), { code: 'ENOENT' });

    await writeFile(rekeyPath, JSON.stringify({ ...prepared, phase: 'config-committed' }));
    assert.deepEqual(
      await reconcilePendingRekey({ state: before, authoritativeAccounts: [target], statePath, rekeyPath }),
      after,
      'config-committed completes new state',
    );
    assert.deepEqual(JSON.parse(await readFile(statePath, 'utf8')), after);

    await writeFile(rekeyPath, JSON.stringify({ ...prepared, phase: 'state-committed' }));
    assert.deepEqual(
      await reconcilePendingRekey({ state: after, authoritativeAccounts: [target], statePath, rekeyPath }),
      after,
    );
    await assert.rejects(readFile(rekeyPath), { code: 'ENOENT' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rekey recovery rejects both, neither, unrelated, malformed, and collision evidence', () => {
  const source = { type: 'oauth', accountUuid: 'p1', orgName: 'Acme' };
  const target = { type: 'oauth', accountUuid: 'p1', orgUuid: 'o1' };
  const before = createCanonicalState({
    accounts: { 'u:p1:n:acme': { quota: { unified5h: 0.1 } } },
    activeAccountId: 'u:p1:n:acme',
  });
  const after = createCanonicalState({
    ...before,
    accounts: { 'u:p1:o:o1': before.accounts['u:p1:n:acme'] },
    activeAccountId: 'u:p1:o:o1',
  });
  const record = createRekeyRecord({ from: source, to: target, beforeState: before, afterState: after });
  const both = createCanonicalState({
    ...before,
    accounts: { ...before.accounts, 'u:p1:o:o1': { quota: {} } },
  });
  const neither = createCanonicalState({
    ...before,
    accounts: { 'u:p2:o:o2': before.accounts['u:p1:n:acme'] },
    activeAccountId: 'u:p2:o:o2',
  });

  assert.throws(() => reconcileRekeyRecord(record, both, [source]), /Canonical state rekey authority failed/);
  assert.throws(() => reconcileRekeyRecord(record, neither, [source]), /Canonical state rekey authority failed/);
  assert.throws(() => reconcileRekeyRecord(record, before, [{ type: 'oauth', accountUuid: 'p3', orgUuid: 'o3' }]), /Canonical state rekey authority failed/);
  assert.throws(() => reconcileRekeyRecord({ ...record, extra: true }, before, [source]), /Canonical state validate rekey failed/);
  assert.throws(
    () => reconcileRekeyRecord({ ...record, phase: 'config-committed' }, both, [target]),
    /Canonical state rekey authority failed/,
  );
});

test('canonical validation and legacy migration reject nested secrets and unknown state fields', () => {
  const state = () => ({
    accounts: {
      'u:p1:o:o1': {
        quota: { unified5h: 0.1, modelWeekly: { '7d_oi': { utilization: 0.2, reset: 1 } } },
        usage: { totalRequests: 1 },
        throttle: { until: 1 },
        convergence: { attempts: 1, status: 'warming' },
        reset: { at: 1, reason: 'window' },
      },
    },
    activeAccountId: 'u:p1:o:o1',
    template: { model: 'claude-test', version: '2023-06-01', beta: null, system: [{ type: 'text', text: 'ping' }] },
  });
  assert.doesNotThrow(() => createCanonicalState(state()));

  for (const mutate of [
    value => { value.accounts['u:p1:o:o1'].quota.accessToken = 'secret'; },
    value => { value.accounts['u:p1:o:o1'].usage.token = 'secret'; },
    value => { value.accounts['u:p1:o:o1'].throttle.refreshToken = 'secret'; },
    value => { value.accounts['u:p1:o:o1'].convergence.apiKey = 'secret'; },
    value => { value.accounts['u:p1:o:o1'].reset.credential = 'secret'; },
    value => { value.template.system[0].accessToken = 'secret'; },
  ]) {
    const value = state();
    mutate(value);
    assert.throws(() => createCanonicalState(value), /Canonical state validate/);
  }

  assert.throws(
    () => migrateLegacyState([{ accountUuid: 'p1', orgUuid: 'o1', quota: { unified5h: 0.1, accessToken: 'secret' } }]),
    /Canonical state (validate|migrate)/,
  );
});

test('legacy quota wrapper migrates while dropping transient unified status', () => {
  const migrated = migrateLegacyState({
    quota: [{
      accountUuid: 'p1',
      orgName: 'Acme',
      name: 'user@example.com',
      quota: {
        unified5h: 0.25,
        unified5hReset: 30_000,
        unifiedStatus: 'allowed_warning',
      },
    }],
  });
  const [account] = Object.values(migrated.accounts);
  assert.equal(account.quota.unified5h, 0.25);
  assert.equal(account.quota.unified5hReset, 30_000);
  assert.equal(Object.hasOwn(account.quota, 'unifiedStatus'), false);
});

test('legacy migration rejects discarded root/account secrets and malformed transient fields', () => {
  const account = {
    accountUuid: 'p1',
    orgName: 'Acme',
    name: 'user@example.com',
    quota: { unified5h: 0.25 },
  };
  for (const legacy of [
    { quota: [account], accessToken: 'secret' },
    { quota: [{ ...account, refreshToken: 'secret' }] },
    { quota: [{ ...account, unknown: true }] },
    { quota: [{ ...account, quota: 'invalid' }] },
    { quota: [{ ...account, usage: 'invalid' }] },
    { quota: [{ ...account, rateLimitedUntil: 'tomorrow' }] },
    { quota: [{ ...account, quota: { unifiedStatus: { accessToken: 'secret' } } }] },
  ]) {
    assert.throws(() => migrateLegacyState(legacy), /Canonical state migrate/);
  }
});