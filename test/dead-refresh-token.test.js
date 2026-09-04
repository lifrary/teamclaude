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
  assert.strictEqual(m.accounts[0]._deadRefreshToken, undefined,
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
