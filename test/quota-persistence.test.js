import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';
import { createCanonicalState, rekeyCanonicalState, getStatePath } from '../src/config.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

test('exportCanonicalState persists credential-free state under exact org-aware identities', () => {
  const am = new AccountManager([
    oauth('a@x.com (Acme)', { accessToken: 'access-secret', refreshToken: 'refresh-secret', accountUuid: 'p1', orgUuid: 'o1' }),
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
  ], 0.98);
  am.accounts[0].quota.unified7d = 0.42;
  const state = am.exportCanonicalState();

  assert.deepEqual(Object.keys(state.accounts).sort(), ['u:p1:o:o1', 'u:p1:o:o2']);
  assert.deepEqual(Object.keys(state.accounts['u:p1:o:o1']).sort(), ['quota', 'usage']);
  assert.equal(state.accounts['u:p1:o:o1'].quota.unified7d, 0.42);
  assert.equal(JSON.stringify(state).includes('access-secret'), false);
  assert.equal(JSON.stringify(state).includes('refresh-secret'), false);
});

test('quota survives a canonical export → restore round-trip', () => {
  const am1 = new AccountManager([oauth('a', { accountUuid: 'p1', orgUuid: 'o1' })], 0.98);
  const future = Date.now() + 3600_000;
  Object.assign(am1.accounts[0].quota, { unified5h: 0.3, unified7d: 0.6, unified7dReset: future });

  const am2 = new AccountManager([oauth('a', { accountUuid: 'p1', orgUuid: 'o1' })], 0.98);
  am2.restoreCanonicalState(am1.exportCanonicalState());

  assert.equal(am2.accounts[0].quota.unified5h, 0.3);
  assert.equal(am2.accounts[0].quota.unified7d, 0.6);
  assert.equal(am2.accounts[0].quota.unified7dReset, future);
  assert.equal(am2.accounts[0].probing, false); // weekly window known → not probing
});

test('canonical restore matches the complete org-aware identity, not array position', () => {
  const am1 = new AccountManager([
    oauth('a@x.com (Acme)', { accountUuid: 'p1', orgUuid: 'o1' }),
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
  ], 0.98);
  am1.accounts[0].quota.unified7d = 0.1; // Acme
  am1.accounts[1].quota.unified7d = 0.9; // Personal
  const saved = am1.exportCanonicalState();

  // Reverse the order in the new manager — restore must still match by org.
  const am2 = new AccountManager([
    oauth('a@x.com (Personal)', { accountUuid: 'p1', orgUuid: 'o2' }),
    oauth('a@x.com (Acme)', { accountUuid: 'p1', orgUuid: 'o1' }),
  ], 0.98);
  am2.restoreCanonicalState(saved);

  assert.equal(am2.accounts[0].quota.unified7d, 0.9); // Personal
  assert.equal(am2.accounts[1].quota.unified7d, 0.1); // Acme
});

test('a canonically restored window whose reset already passed is cleared on first use', () => {
  const source = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  source.accounts[0].quota.unified7d = 0.5;
  source.accounts[0].quota.unified7dReset = 1000; // reset far in the past
  const am = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am.restoreCanonicalState(source.exportCanonicalState());
  assert.equal(am.accounts[0].quota.unified7d, 0.5); // restored...
  am.refreshExpiredQuotas();
  assert.equal(am.accounts[0].quota.unified7d, null); // ...then cleared as stale
});

test('restoreCanonicalState ignores a missing payload', () => {
  const am = new AccountManager([oauth('a', { accountUuid: 'p1' })], 0.98);
  am.restoreCanonicalState(undefined);
  am.restoreCanonicalState(null);
  assert.equal(am.accounts[0].quota.unified7d, null); // unchanged, no throw
});

test('getStatePath sits beside the config as a .state.json sibling', () => {
  const prev = process.env.TEAMCLAUDE_CONFIG;
  process.env.TEAMCLAUDE_CONFIG = '/tmp/teamclaude-xyz.json';
  try {
    assert.equal(getStatePath(), '/tmp/teamclaude-xyz.state.json');
  } finally {
    if (prev === undefined) delete process.env.TEAMCLAUDE_CONFIG;
    else process.env.TEAMCLAUDE_CONFIG = prev;
  }
});
test('canonical quota state is keyed by AccountId and rejects a replaced same-name identity', () => {
  const first = new AccountManager([
    oauth('same@example.com', { accountUuid: 'old', orgUuid: 'org' }),
  ], 0.98);
  first.accounts[0].quota.unified7d = 0.61;
  first.accounts[0].usage.totalRequests = 3;
  const state = first.exportCanonicalState();

  assert.deepEqual(Object.keys(state.accounts), ['u:old:o:org']);
  assert.deepEqual(Object.keys(state.accounts['u:old:o:org']).sort(), ['quota', 'usage']);

  const replaced = new AccountManager([
    oauth('same@example.com', { accountUuid: 'new', orgUuid: 'org' }),
  ], 0.98);
  replaced.restoreCanonicalState(state);
  assert.equal(replaced.accounts[0].quota.unified7d, null);
  assert.equal(replaced.accounts[0].usage.totalRequests, 0);
});
test('replaceAccount publishes a new canonical object while an in-flight object drains', () => {
  const am = new AccountManager([
    oauth('same@example.com', { accountUuid: 'p1', orgName: 'Acme' }),
  ], 0.98);
  const held = am.accounts[0];
  held.inFlight = 1;
  held.quota.unified7d = 0.42;

  const replacement = am.replaceAccount(held, oauth('same@example.com', {
    accountUuid: 'p1',
    orgUuid: 'o1',
  }));

  assert.notEqual(replacement, held);
  assert.equal(held.accountIdKey, 'u:p1:n:acme');
  assert.equal(replacement.accountIdKey, 'u:p1:o:o1');
  assert.equal(replacement.quota.unified7d, 0.42);
  am.releaseAccount(held);
  assert.equal(held.inFlight, 0);
  assert.equal(replacement.inFlight, 0);
});
test('org-name rekey preserves credential-free quota state for serialized restart recovery', () => {
  const before = createCanonicalState({
    accounts: { 'u:p1:n:acme': { quota: { unified7d: 0.42 }, usage: { totalRequests: 3 } } },
    activeAccountId: 'u:p1:n:acme',
  });
  const reloaded = JSON.parse(JSON.stringify(before));
  const after = rekeyCanonicalState(reloaded, 'u:p1:n:acme', 'u:p1:o:o1');
  assert.deepEqual(after.accounts['u:p1:o:o1'], before.accounts['u:p1:n:acme']);
  assert.equal(after.activeAccountId, 'u:p1:o:o1');
  assert.doesNotMatch(JSON.stringify(after), /accessToken|refreshToken|apiKey/);
});
