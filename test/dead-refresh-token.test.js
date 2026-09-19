import { test } from 'node:test';
import assert from 'node:assert';
import { AccountManager } from '../src/account-manager.js';

// An account whose token is already expiring, so ensureTokenFresh always tries.
function mgr(refreshFn) {
  return new AccountManager([{
    name: 'a', type: 'oauth',
    accessToken: 'at-old', refreshToken: 'rt-dead', expiresAt: Date.now() - 1000,
  }], 0.98, { refreshFn });
}

function authError(status = 400) {
  const e = new Error(`Token refresh failed (${status}): {"error":"invalid_grant"}`);
  e.status = status;
  return e;
}

test('a removed account cannot refresh or overwrite the account shifted into its index', async () => {
  let calls = 0;
  const m = mgr(async () => { calls++; return { accessToken: 'new', refreshToken: 'new-r', expiresAt: Date.now() + 3600_000 }; });
  const retired = m.accounts[0];
  m.addAccount({ name: 'b', type: 'oauth', accessToken: 'b', refreshToken: 'b-r', expiresAt: Date.now() - 1 });
  m.removeAccount(0);
  await m.ensureTokenFresh(retired, true);
  m.applyUsageData(retired, { fiveHour: { utilization: 0.9 } });
  assert.equal(calls, 0);
  assert.equal(m.accounts[0].credential, 'b');
  assert.equal(m.accounts[0].quota.unified5h, null);
});

test('Codex refresh is dispatched only to the Codex endpoint with an object handle', async () => {
  let anthropic = 0, codex = 0;
  const m = new AccountManager([{
    name: 'codex', type: 'oauth', provider: 'codex', accountId: 'seat',
    accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1,
  }], 0.98, {
    refreshFn: async () => { anthropic++; throw new Error('wrong provider'); },
    codexRefreshFn: async () => { codex++; return { accessToken: 'fresh', refreshToken: 'fresh-rt', expiresAt: Date.now() + 3600_000 }; },
  });
  assert.equal((await m.ensureTokenFresh(m.accounts[0])).ok, true);
  assert.equal(codex, 1);
  assert.equal(anthropic, 0);
  assert.equal(m.accounts[0].accountId, 'seat');
});

test('a rejected refresh token is not re-sent (no OAuth flood)', async () => {
  let calls = 0;
  const m = mgr(async () => { calls++; throw authError(400); });
  await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 1);
  assert.strictEqual(m.accounts[0].status, 'error');
  // warmer/prober keep calling this for every account regardless of availability
  for (let i = 0; i < 25; i++) await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 1, 'dead token must be sent exactly once, not once per call');
});

test('force=true does not bypass the dead-token guard', async () => {
  let calls = 0;
  const m = mgr(async () => { calls++; throw authError(401); });
  await m.ensureTokenFresh(0);
  await m.ensureTokenFresh(0, true);
  assert.strictEqual(calls, 1, 'a known-dead token stays dead even under force');
});

test('a TRANSIENT failure is not guarded — it retries', async () => {
  let calls = 0;
  const m = mgr(async () => { calls++; const e = new Error('socket hang up'); e.status = 500; throw e; });
  await m.ensureTokenFresh(0);
  await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 2, 'network/5xx must keep retrying (token may still be good)');
  // The guard is what this file is about, and it must stay disarmed: the refresh
  // token was never rejected, only unreachable.
  assert.strictEqual(m.accounts[0]._deadRefreshToken, null,
    'a transient failure must not arm the dead-token guard');

  // DELIBERATE DIVERGENCE FROM UPSTREAM — do not "restore" this on the next sync.
  // Upstream asserts `status !== 'error'` here. This fork parks on
  // `isAuthRejection || accessExpired`, and mgr() builds the account with an
  // ALREADY-EXPIRED access token, so this case takes the accessExpired arm: there
  // is no valid credential left to serve a request with, so the account is
  // sidelined rather than handed to a client that would only get a 401. What
  // makes that safe is that the park is tagged refresh-caused, so the keep-alive
  // sweep revives it the moment any refresh succeeds — no restart, no re-login.
  // Assert the healability, which is the property that actually matters, rather
  // than the status, which is the one the two designs disagree about.
  assert.strictEqual(m.accounts[0].status, 'error');
  assert.strictEqual(m.accounts[0]._errorFromRefresh, true,
    'a transient park must stay self-healing on the next successful refresh');
});

test('a transient park heals on the next successful refresh, guard still disarmed', async () => {
  let calls = 0;
  const m = mgr(async () => {
    calls++;
    if (calls === 1) { const e = new Error('socket hang up'); e.status = 500; throw e; }
    return { accessToken: 'at-new', refreshToken: 'rt-new', expiresAt: Date.now() + 3600_000 };
  });
  await m.ensureTokenFresh(0);
  assert.strictEqual(m.accounts[0].status, 'error', 'parked by the transient failure');
  await m.ensureTokenFresh(0);
  assert.strictEqual(m.accounts[0].status, 'active', 'the sweep heals it without a re-login');
  assert.strictEqual(m.accounts[0]._deadRefreshToken, null);
});

test('guard lifts automatically when a NEW refresh token arrives (re-login)', async () => {
  let calls = 0;
  const m = mgr(async (rt) => {
    calls++;
    if (rt === 'rt-dead') throw authError(400);
    return { accessToken: 'at-new', refreshToken: 'rt-fresh2', expiresAt: Date.now() + 3600_000 };
  });
  await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 1);
  await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 1, 'still guarded while the token is unchanged');

  // re-login / config reload hands the account a fresh token
  m.updateAccountTokens(0, { accessToken: 'at-x', refreshToken: 'rt-fresh', expiresAt: Date.now() - 1000 });
  await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 2, 'a different refresh token must be attempted');
  assert.strictEqual(m.accounts[0].status, 'active');
});

test('re-enabling a disabled account clears the guard (operator escape hatch)', async () => {
  let calls = 0;
  const m = mgr(async () => { calls++; throw authError(403); });
  await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 1);
  m.setDisabled(0, true);
  m.setDisabled(0, false);
  await m.ensureTokenFresh(0);
  assert.strictEqual(calls, 2, 'explicit re-enable means "try again"');
});

test('a successful refresh clears any stale guard', async () => {
  let mode = 'fail';
  let calls = 0;
  const m = mgr(async () => {
    calls++;
    if (mode === 'fail') throw authError(400);
    return { accessToken: 'at2', refreshToken: 'rt2', expiresAt: Date.now() - 1000 };
  });
  await m.ensureTokenFresh(0);            // dead → guard armed on 'rt-dead'
  m.accounts[0].refreshToken = 'rt-other'; // a different token arrives
  mode = 'ok';
  await m.ensureTokenFresh(0);            // succeeds → guard cleared
  assert.strictEqual(m.accounts[0]._deadRefreshToken, null);
  const before = calls;
  await m.ensureTokenFresh(0);            // token still expiring → tries again freely
  assert.strictEqual(calls, before + 1, 'no lingering guard after a success');
});

// A re-import can supply a NEW access token with the SAME dead refresh token
// (updateAccountTokens resets status to 'active'). The guard still blocks the
// refresh, so the account must read as errored again or the access token's 401
// would be relayed to the client instead of rotating.
test('a re-imported access token with the same dead refresh token reads as errored, not retried', async () => {
  let calls = 0;
  const m = mgr(async () => { calls++; throw authError(400); });
  await m.ensureTokenFresh(0);
  assert.strictEqual(m.accounts[0].status, 'error');

  m.updateAccountTokens(0, { accessToken: 'at-reimported', refreshToken: 'rt-dead', expiresAt: Date.now() - 1000 });
  assert.strictEqual(m.accounts[0].status, 'active', 'updateAccountTokens clears the error state');

  await m.ensureTokenFresh(0, true);      // the 401 path forces a refresh
  assert.strictEqual(calls, 1, 'the dead token is still not re-sent');
  assert.strictEqual(m.accounts[0].status, 'error', 'but the account is sidelined so the request rotates');
});

test('the dead-token field is part of the account record from construction', () => {
  const m = mgr(async () => { throw authError(400); });
  assert.ok('_deadRefreshToken' in m.accounts[0]);
  assert.strictEqual(m.accounts[0]._deadRefreshToken, null);
});

// A config reload or `teamclaude import` can install new tokens WHILE a refresh
// of the old ones is awaiting upstream. The outcome of that call belongs to the
// token that was sent, not to whatever the account holds when it lands.
function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('an invalid_grant for the OLD token does not mark a token imported mid-refresh dead', async () => {
  const d = deferred();
  const m = mgr(async () => d.promise);
  const inflight = m.ensureTokenFresh(0);

  // Import lands while the refresh is in flight and hands over a valid token.
  m.updateAccountTokens(0, { accessToken: 'at-imported', refreshToken: 'rt-imported', expiresAt: Date.now() + 3600_000 });
  d.reject(authError(400));
  await inflight;

  const a = m.accounts[0];
  assert.strictEqual(a._deadRefreshToken, 'rt-dead', 'the token that was SENT is the dead one');
  assert.strictEqual(a.refreshToken, 'rt-imported');
  assert.strictEqual(a.status, 'active', 'the account must not be locked out — its live token was never rejected');
  assert.strictEqual(a.credential, 'at-imported');
});

test('a successful refresh of the OLD token does not overwrite tokens imported mid-refresh', async () => {
  const d = deferred();
  let persisted = 0;
  const m = mgr(async () => d.promise);
  m.onTokenRefresh(() => { persisted++; });
  const inflight = m.ensureTokenFresh(0);

  m.updateAccountTokens(0, { accessToken: 'at-imported', refreshToken: 'rt-imported', expiresAt: 4_000_000_000_000 });
  const persistedByImport = persisted;
  d.resolve({ accessToken: 'at-stale', refreshToken: 'rt-stale', expiresAt: Date.now() + 3600_000 });
  await inflight;

  const a = m.accounts[0];
  assert.strictEqual(a.refreshToken, 'rt-imported', 'the stale result is discarded');
  assert.strictEqual(a.credential, 'at-imported');
  assert.strictEqual(a.expiresAt, 4_000_000_000_000);
  assert.strictEqual(persisted, persistedByImport, 'nothing stale is persisted to config');
  assert.strictEqual(a._refreshPromise, null, 'the coalescing slot is released');
});

test('an unchanged token is refreshed normally (the guard only fires on a swap)', async () => {
  const tokens = { accessToken: 'at-new', refreshToken: 'rt-new', expiresAt: Date.now() + 3600_000 };
  const m = mgr(async () => tokens);
  const persisted = [];
  m.onTokenRefresh((index, refreshed, lineage) => persisted.push({ index, refreshed, lineage }));
  await m.ensureTokenFresh(0);
  assert.strictEqual(m.accounts[0].refreshToken, 'rt-new');
  assert.strictEqual(m.accounts[0].credential, 'at-new');
  assert.deepStrictEqual(persisted, [{
    index: 0, refreshed: tokens, lineage: { previousRefreshToken: 'rt-dead' },
  }]);
});

test('external token updates persist the previous refresh-token lineage before mutation', () => {
  const m = mgr(async () => { throw new Error('external updates must not refresh'); });
  const persisted = [];
  m.onTokenRefresh((index, refreshed, lineage) => persisted.push({ index, refreshed, lineage }));
  m.updateAccountTokens(0, { accessToken: 'at-imported', refreshToken: 'rt-imported', expiresAt: 4_000_000_000_000 });
  m.updateAccountTokens(0, { accessToken: 'at-next', expiresAt: 4_000_000_000_001 });
  assert.deepStrictEqual(persisted, [
    {
      index: 0,
      refreshed: { accessToken: 'at-imported', refreshToken: 'rt-imported', expiresAt: 4_000_000_000_000 },
      lineage: { previousRefreshToken: 'rt-dead' },
    },
    {
      index: 0,
      refreshed: { accessToken: 'at-next', refreshToken: 'rt-imported', expiresAt: 4_000_000_000_001 },
      lineage: { previousRefreshToken: 'rt-imported' },
    },
  ]);
});

// #315: a third-party backend's credential must never be sent to Anthropic's
// token endpoint. The prober and warmer already skip `upstream` accounts; the
// send path and the 401 retry go through here and did not.
test('an account with a third-party upstream is never refreshed against Anthropic', async () => {
  let calls = 0;
  const m = new AccountManager([{
    name: 'glm', type: 'oauth', upstream: 'https://glm.example/anthropic',
    accessToken: 'third-party-key', refreshToken: 'rt-third-party', expiresAt: Date.now() - 1000,
  }], 0.98, { refreshFn: async () => { calls++; return { accessToken: 'x', refreshToken: 'y', expiresAt: Date.now() + 1e6 }; } });
  await m.ensureTokenFresh(0);
  await m.ensureTokenFresh(0, true);
  assert.strictEqual(calls, 0, 'the refresh token was not sent anywhere');
  assert.strictEqual(m.accounts[0].credential, 'third-party-key', 'the credential is untouched');
});
