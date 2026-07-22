import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer, resolveAccountPin } from '../src/server.js';
import { accountIdKey } from '../src/identity.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

const pin = account => encodeURIComponent(accountIdKey(account));

// ── resolveAccountPin (unit) ─────────────────────────────────────────────────

test('resolveAccountPin resolves canonical keys to the exact live account object', () => {
  const am = new AccountManager([
    oauth('alpha', { accountUuid: 'person-1', orgUuid: 'org-1' }),
    oauth('alpha', { accountUuid: 'person-1', orgUuid: 'org-2' }),
  ], 0.98);

  assert.equal(resolveAccountPin(am, accountIdKey(am.accounts[0])), am.accounts[0]);
  assert.equal(resolveAccountPin(am, accountIdKey(am.accounts[1])), am.accounts[1]);
});

test('resolveAccountPin rejects numeric pins and ambiguous legacy names', () => {
  const am = new AccountManager([
    oauth('alpha', { accountUuid: 'person-1', orgUuid: 'org-1' }),
    oauth('alpha', { accountUuid: 'person-1', orgUuid: 'org-2' }),
    oauth('beta'),
  ], 0.98);

  assert.equal(resolveAccountPin(am, '0'), null);
  assert.equal(resolveAccountPin(am, '1'), null);
  assert.equal(resolveAccountPin(am, 'alpha'), null);
  assert.equal(resolveAccountPin(am, 'beta'), am.accounts[2]);
  assert.equal(resolveAccountPin(am, 'nope'), null);
});

test('a canonical pin remains bound to its account after another account is removed', () => {
  const am = new AccountManager([oauth('alpha'), oauth('beta')], 0.98);
  const beta = am.accounts[1];
  const betaKey = accountIdKey(beta);

  am.removeAccount(0);

  assert.equal(resolveAccountPin(am, betaKey), beta);
  assert.equal(resolveAccountPin(am, betaKey), am.accounts[0]);
});

// ── end-to-end pin routing (integration) ─────────────────────────────────────

// Stand up a mock upstream that records the path and Authorization it received,
// so we can prove which account a pinned request was routed to and that the
// /tc-acct/<pin> prefix was stripped before forwarding.
async function withProxy(run, accounts = [oauth('alpha'), oauth('beta')]) {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push({ path: req.url, auth: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(accounts, 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);
  try {
    return await run({ proxyPort, seen, am });
  } finally {
    proxy.close();
    upstream.close();
  }
}

const post = (url) => fetch(url, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ model: 'x', messages: [] }),
});

test('a canonical /tc-acct/<key> request is routed to that exact account, prefix stripped', async () => {
  await withProxy(async ({ proxyPort, seen, am }) => {
    const res = await post(`http://127.0.0.1:${proxyPort}/tc-acct/${pin(am.accounts[1])}/v1/messages`);
    await res.text();
    assert.equal(res.status, 200);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].path, '/v1/messages');          // prefix stripped
    assert.equal(seen[0].auth, 'Bearer t-beta');         // routed to 'beta', not rotation default
  });
});

test('numeric pins are rejected and never reach upstream', async () => {
  await withProxy(async ({ proxyPort, seen }) => {
    const res = await post(`http://127.0.0.1:${proxyPort}/tc-acct/0/v1/messages`);
    await res.text();
    assert.equal(res.status, 404);
    assert.equal(seen.length, 0);
  });
});
test('duplicate legacy names fail closed while canonical multi-org pins remain exact', async () => {
  const accounts = [
    oauth('shared', { accessToken: 't-org-1', accountUuid: 'person-1', orgUuid: 'org-1' }),
    oauth('shared', { accessToken: 't-org-2', accountUuid: 'person-1', orgUuid: 'org-2' }),
  ];
  await withProxy(async ({ proxyPort, seen, am }) => {
    const ambiguous = await post(`http://127.0.0.1:${proxyPort}/tc-acct/shared/v1/messages`);
    await ambiguous.text();
    assert.equal(ambiguous.status, 404);
    assert.equal(seen.length, 0);

    const canonical = await post(`http://127.0.0.1:${proxyPort}/tc-acct/${pin(am.accounts[1])}/v1/messages`);
    await canonical.text();
    assert.equal(canonical.status, 200);
    assert.equal(seen[0].auth, 'Bearer t-org-2');
  }, accounts);
});

test('an unknown pin returns 404 and never reaches upstream', async () => {
  await withProxy(async ({ proxyPort, seen }) => {
    const res = await post(`http://127.0.0.1:${proxyPort}/tc-acct/ghost/v1/messages`);
    const body = await res.json();
    assert.equal(res.status, 404);
    assert.equal(body.error.type, 'not_found_error');
    assert.equal(seen.length, 0);
  });
});

test('a canonical pin overrides rotation even when another account is the active one', async () => {
  await withProxy(async ({ proxyPort, seen, am }) => {
    am.currentIndex = 0; // rotation would pick 'alpha'
    const res = await post(`http://127.0.0.1:${proxyPort}/tc-acct/${pin(am.accounts[1])}/v1/messages`);
    await res.text();
    assert.equal(seen[0].auth, 'Bearer t-beta'); // pin wins over the active account
  });
});

test('a canonical pin survives account removal and reindexing', async () => {
  await withProxy(async ({ proxyPort, seen, am }) => {
    const beta = am.accounts[1];
    const betaPin = pin(beta);
    am.removeAccount(0);

    const res = await post(`http://127.0.0.1:${proxyPort}/tc-acct/${betaPin}/v1/messages`);
    await res.text();
    assert.equal(res.status, 200);
    assert.equal(seen[0].auth, 'Bearer t-beta');
  });
});

test('a normal (unpinned) request still rotates as before', async () => {
  await withProxy(async ({ proxyPort, seen }) => {
    const res = await post(`http://127.0.0.1:${proxyPort}/v1/messages`);
    await res.text();
    assert.equal(res.status, 200);
    assert.equal(seen[0].path, '/v1/messages');
    assert.equal(seen[0].auth, 'Bearer t-alpha'); // default rotation → first account
  });
});
