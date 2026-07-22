import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  accountId, accountIdKey, createIdentityRegistry, digestAccountId, parseAccountIdKey,
  IdentityAmbiguityError, orgKey, sameIdentity, emailOf, matchAccounts,
} from '../src/identity.js';
import { accountIdDigest, configIdentityDigest, identityTupleDigest } from '../src/config.js';

test('orgKey prefers orgUuid, falls back to orgName, else null', () => {
  assert.equal(orgKey({ orgUuid: 'u1', orgName: 'Acme' }), 'u1');
  assert.equal(orgKey({ orgName: 'Acme' }), 'acme');
  assert.equal(orgKey({}), null);
  assert.equal(orgKey(null), null);
});

test('same person, same org → same identity', () => {
  const a = { accountUuid: 'p1', orgUuid: 'o1' };
  const b = { accountUuid: 'p1', orgUuid: 'o1' };
  assert.equal(sameIdentity(a, b), true);
});

test('same person, different org → distinct identities', () => {
  const a = { accountUuid: 'p1', orgUuid: 'o1' };
  const b = { accountUuid: 'p1', orgUuid: 'o2' };
  assert.equal(sameIdentity(a, b), false);
});

test('different person → distinct identities regardless of org', () => {
  const a = { accountUuid: 'p1', orgUuid: 'o1' };
  const b = { accountUuid: 'p2', orgUuid: 'o1' };
  assert.equal(sameIdentity(a, b), false);
});

test('unknown-org UUID does not silently match a complete identity', () => {
  const legacy = { accountUuid: 'p1', name: 'a@x.com' };
  const fresh = { accountUuid: 'p1', orgUuid: 'o1', name: 'a@x.com' };
  assert.equal(sameIdentity(legacy, fresh), false);
  assert.throws(
    () => createIdentityRegistry([legacy, fresh]).get(fresh),
    IdentityAmbiguityError,
  );
});

test('canonical IDs normalize org names and use deterministic no-UUID names', () => {
  assert.deepEqual(accountId({ accountUuid: ' P1 ', orgName: ' Acme ' }), {
    tag: 'uuid-org-name', accountUuid: 'p1', orgName: 'acme',
  });
  assert.equal(accountIdKey({ name: ' API-1 ' }), 'n:api-1');
  assert.match(digestAccountId({ accountUuid: 'p1', orgName: 'Acme' }), /^[a-f0-9]{64}$/);
});
test('org-name rekey digest projections survive process-style serialized reloads', () => {
  const account = {
    type: 'oauth',
    name: 'person@example.com (Acme)',
    accountUuid: ' P1 ',
    orgName: ' Acme ',
    accessToken: 'secret',
  };
  const reloaded = JSON.parse(JSON.stringify(account));
  assert.equal(accountIdDigest(account), accountIdDigest(reloaded));
  assert.equal(identityTupleDigest(account), identityTupleDigest(reloaded));
  assert.equal(configIdentityDigest(account), configIdentityDigest(reloaded));
  assert.doesNotMatch(configIdentityDigest(account), /Acme|secret|p1/i);
});
test('parseAccountIdKey round-trips punctuation-safe name keys', () => {
  const key = 'u:person-1:n:Acme: R&D / Europe';
  assert.deepEqual(parseAccountIdKey(key), {
    tag: 'uuid-org-name', accountUuid: 'person-1', orgName: 'Acme: R&D / Europe',
  });
  assert.deepEqual(parseAccountIdKey('n:api:key/with punctuation'), {
    tag: 'name', name: 'api:key/with punctuation',
  });
  assert.throws(() => parseAccountIdKey('n:'), IdentityAmbiguityError);
});

test('registry rejects duplicate complete and unknown-org identities', () => {
  assert.throws(
    () => createIdentityRegistry([{ accountUuid: 'p1', orgUuid: 'o1' }, { accountUuid: 'P1', orgUuid: 'O1' }]),
    IdentityAmbiguityError,
  );
  assert.throws(
    () => createIdentityRegistry([{ accountUuid: 'p1' }, { accountUuid: 'P1' }]),
    IdentityAmbiguityError,
  );
});

test('apikey / no-uuid accounts fall back to name matching', () => {
  assert.equal(sameIdentity({ name: 'k1' }, { name: 'k1' }), true);
  assert.equal(sameIdentity({ name: 'k1' }, { name: 'k2' }), false);
});

test('emailOf strips a " (org)" suffix', () => {
  assert.equal(emailOf({ name: 'a@x.com (Acme)' }), 'a@x.com');
  assert.equal(emailOf({ name: 'a@x.com' }), 'a@x.com');
  assert.equal(emailOf({}), '');
});

// resolveAccount in index.js is built on matchAccounts; cover the routing here.
const ACCTS = [
  { name: 'a@x.com (Acme)', accountUuid: 'p1', orgUuid: 'o-acme', orgName: 'Acme' },
  { name: 'a@x.com (Personal)', accountUuid: 'p1', orgUuid: 'o-pers', orgName: 'Personal' },
  { name: 'b@y.com', accountUuid: 'p2', orgUuid: 'o-b', orgName: 'BizCo' },
];

test('matchAccounts: exact display-name match wins', () => {
  const m = matchAccounts(ACCTS, 'a@x.com (Acme)');
  assert.equal(m.length, 1);
  assert.equal(m[0].orgName, 'Acme');
});

test('matchAccounts: bare email is ambiguous across orgs', () => {
  const m = matchAccounts(ACCTS, 'a@x.com');
  assert.equal(m.length, 2);
});

test('matchAccounts: --org narrows by org name or uuid prefix', () => {
  assert.equal(matchAccounts(ACCTS, 'a@x.com', 'Personal').length, 1);
  assert.equal(matchAccounts(ACCTS, 'a@x.com', 'o-acme').length, 1);
  assert.equal(matchAccounts(ACCTS, 'a@x.com', 'o-ac')[0].orgName, 'Acme'); // uuid prefix
});

test('matchAccounts: unique email needs no org', () => {
  assert.equal(matchAccounts(ACCTS, 'b@y.com').length, 1);
});

test('matchAccounts: no match returns empty', () => {
  assert.equal(matchAccounts(ACCTS, 'nobody@z.com').length, 0);
});
