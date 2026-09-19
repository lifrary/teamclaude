import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';
import { syncAccountsFromDisk } from '../src/sync-accounts.js';

// syncAccountsFromDisk pairs disk entries to running accounts with a greedy 1:1
// claimer, because identity alone is ambiguous: sameIdentity compares orgKey
// only when BOTH sides carry one, and falls back to comparing names when no
// accountUuid is present. The memConfig side must pair the same way — a
// first-match scan there writes a third-party-backend binding onto the wrong
// account, which the next TUI save then persists to disk.
//
// These build the ambiguous state by hand; real configs mostly avoid it.

// The manager receives org identity that memConfig may still lack — the sync
// backfills orgUuid/orgName onto the manager object only, so a memConfig entry
// can sit without an orgKey indefinitely.
function twoOrgsOneUuid() {
  const disk = [
    { name: 'user@example.com (Acme)', type: 'apikey', apiKey: 'k-acme', accountUuid: 'uuid-shared', orgUuid: 'org-acme' },
    { name: 'user@example.com (Globex)', type: 'apikey', apiKey: 'k-globex', accountUuid: 'uuid-shared', orgUuid: 'org-globex' },
  ];
  // memConfig's first entry predates org disambiguation: same accountUuid, no
  // orgUuid, so sameIdentity() says "same account" against BOTH disk entries.
  const mem = [
    { name: 'user@example.com (Acme)', type: 'apikey', apiKey: 'k-acme', accountUuid: 'uuid-shared' },
    { name: 'user@example.com (Globex)', type: 'apikey', apiKey: 'k-globex', accountUuid: 'uuid-shared', orgUuid: 'org-globex' },
  ];
  return { disk, mem };
}

// No accountUuid anywhere: sameIdentity falls back to name equality, so two
// same-named apikey entries are mutually ambiguous.
function twoApiKeysOneName() {
  const disk = [
    { name: 'shared-name', type: 'apikey', apiKey: 'k-first' },
    { name: 'shared-name', type: 'apikey', apiKey: 'k-second' },
  ];
  return { disk, mem: disk.map(a => ({ ...a })) };
}

test('a second disk entry sharing an accountUuid mirrors onto its own memConfig entry', async () => {
  const { disk, mem } = twoOrgsOneUuid();
  const am = new AccountManager(disk.map(a => ({ ...a })), 0.98);

  // The Globex account (second entry) gains a third-party backend on disk.
  disk[1].upstream = 'https://api.example.test/anthropic';
  disk[1].modelMap = { 'claude-sonnet-4-6': 'other-model' };

  await syncAccountsFromDisk({ accounts: disk }, { accounts: mem }, am);

  assert.equal(mem[1].upstream, 'https://api.example.test/anthropic', 'the edited entry must receive the binding');
  assert.equal(mem[0].upstream, undefined, 'the Acme entry must NOT receive another account\'s upstream');
  assert.equal(mem[0].modelMap, undefined, 'the Acme entry must NOT receive another account\'s modelMap');
  // The manager side pairs correctly today; assert it stays that way.
  assert.equal(am.accounts[1].upstream, 'https://api.example.test/anthropic');
  assert.equal(am.accounts[0].upstream, null);
});

test('two apikey accounts sharing a canonical name are rejected rather than greedily paired', () => {
  const { mem } = twoApiKeysOneName();
  assert.throws(() => new AccountManager(mem, 0.98), /Duplicate complete account identity/);
});

// Pairing must not depend on positional alignment either: resolveAccounts drops
// credential-less entries at startup, so memConfig can hold entries the manager
// never received, shifting every later index.
test('pairing survives a memConfig entry the manager never received', async () => {
  const mem = [
    { name: 'tokenless@example.com', type: 'oauth' },
    { name: 'live@example.com', type: 'apikey', apiKey: 'k-live' },
  ];
  // The manager was built from the filtered list — the tokenless entry is absent.
  const am = new AccountManager([mem[1]].map(a => ({ ...a })), 0.98);
  const disk = mem.map(a => ({ ...a }));
  disk[1].upstream = 'https://api.example.test/anthropic';

  await syncAccountsFromDisk({ accounts: disk }, { accounts: mem }, am);

  assert.equal(mem[1].upstream, 'https://api.example.test/anthropic', 'the live account keeps its own binding');
  assert.equal(mem[0].upstream, undefined, 'the dropped entry must not absorb it');
  assert.equal(am.accounts.length, 1, 'credentialless entries are not admitted');
});

test('stable IDs pair reordered rows and reset controls without clobbering fresh tokens', async () => {
  const expiresAt = Date.now() + 3600_000;
  const rows = [
    { id: 'a', name: 'a', type: 'oauth', accessToken: 'live', refreshToken: 'live-r', expiresAt, priority: 1, disabled: true, maxConcurrent: 1 },
    { id: 'b', name: 'b', type: 'apikey', apiKey: 'key' },
  ];
  const am = new AccountManager(rows, 0.98, { maxConcurrent: 3 });
  const mem = { accounts: rows.map(row => ({ ...row })) };
  const edited = {
    ...rows[0], accessToken: 'stale', refreshToken: 'stale-r',
    expiresAt: Math.floor((expiresAt - 60_000) / 1000), priority: null,
    disabled: false, maxConcurrent: 2, maxUsage: 0.8,
    stripRequestFields: ['metadata'], messageThreads: true,
  };
  await syncAccountsFromDisk({ accounts: [rows[1], edited] }, mem, am);
  assert.equal(am.accounts[0].credential, 'live');
  assert.equal(am.accounts[0].refreshToken, 'live-r');
  assert.equal(am.accounts[0].priority, null);
  assert.equal(am.accounts[0].disabled, false);
  assert.equal(am.accounts[0].maxConcurrent, 2);
  assert.equal(am.accounts[0].maxUsage, 0.8);
  assert.deepEqual(mem.accounts[0].stripRequestFields, ['metadata']);
  assert.equal(mem.accounts[0].messageThreads, true);
  await syncAccountsFromDisk({ accounts: [{ ...rows[0], enabled: false }] }, mem, am);
  assert.equal(am.accounts[0].disabled, true);
});

test('identity changes require durable replacement and retain the retired object', async () => {
  const row = { id: 'entry', name: 'person', type: 'apikey', apiKey: 'key', accountUuid: 'person' };
  const am = new AccountManager([row], 0.98);
  const before = am.accounts[0];
  const mem = { accounts: [{ ...row }] };
  const disk = { accounts: [{ ...row, orgUuid: 'org' }] };
  await assert.rejects(syncAccountsFromDisk(disk, mem, am), /durable rekey/);
  assert.equal(before.orgUuid, null);
  let calls = 0;
  await syncAccountsFromDisk(disk, mem, am, {
    rekey: async ({ previous, target, authoritativeConfig }) => {
      calls++;
      assert.equal(previous, before);
      assert.equal(authoritativeConfig, disk);
      return am.replaceAccount(previous, target);
    },
  });
  assert.equal(calls, 1);
  assert.notEqual(am.accounts[0], before);
  assert.equal(before.orgUuid, null);
  assert.equal(am.accounts[0].orgUuid, 'org');
  assert.equal(mem.accounts[0].orgUuid, 'org');
});

test('provider-qualified names never exchange credentials during reload', async () => {
  const rows = [
    { id: 'claude', name: 'same', type: 'apikey', apiKey: 'claude-key' },
    { id: 'codex', name: 'same', provider: 'codex', type: 'oauth', accountId: 'chatgpt', accessToken: 'codex-token' },
  ];
  const am = new AccountManager(rows, 0.98);
  const mem = { accounts: rows.map(row => ({ ...row })) };
  await syncAccountsFromDisk({ accounts: [{ ...rows[1], accessToken: 'new-codex' }, rows[0]] }, mem, am);
  assert.equal(am.accounts[0].credential, 'claude-key');
  assert.equal(am.accounts[1].credential, 'new-codex');
  assert.equal(am.accounts[1].accountId, 'chatgpt');
});

test('a token rotation while resolution awaits wins over the disk snapshot', async () => {
  const row = { id: 'a', name: 'a', type: 'oauth', accessToken: 'old', refreshToken: 'old-r' };
  const am = new AccountManager([row], 0.98);
  const pending = syncAccountsFromDisk(
    { accounts: [{ ...row, accessToken: 'disk', refreshToken: 'disk-r' }] },
    { accounts: [{ ...row }] }, am,
  );
  am.accounts[0].credential = 'rotated';
  am.accounts[0].refreshToken = 'rotated-r';
  await pending;
  assert.equal(am.accounts[0].credential, 'rotated');
  assert.equal(am.accounts[0].refreshToken, 'rotated-r');
});
