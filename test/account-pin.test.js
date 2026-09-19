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

test('template refresh excludes Codex and foreign upstream credentials before maintenance admission', async () => {
  const am = new AccountManager([
    oauth('native'),
    oauth('codex', { provider: 'codex', accountId: 'chatgpt-account' }),
    oauth('foreign', { upstream: 'https://third-party.example' }),
    oauth('lookalike', { upstream: 'https://api.anthropic.com.attacker.example' }),
  ], 0.98);
  const admitted = [];
  const sent = [];
  const refreshed = [];
  const ensureTokenFresh = am.ensureTokenFresh.bind(am);
  am.ensureTokenFresh = async account => {
    refreshed.push(account.name);
    return ensureTokenFresh(account);
  };
  const maintenance = {
    abortController: new AbortController(),
    run: async (account, _kind, _priority, task) => {
      admitted.push(account.name);
      return task();
    },
    shutdown() { this.abortController.abort(); },
  };
  const proxy = createProxyServer(am, { warmupIntervalMs: 0 }, {
    maintenanceCoordinator: maintenance,
    fetch: async (url, options) => {
      sent.push({ url, authorization: options.headers.authorization });
      return new globalThis.Response('{}', {
        headers: { 'anthropic-ratelimit-unified-5h-utilization': '0.1' },
      });
    },
  });
  try {
    assert.equal(proxy.importProbeTemplate({ model: 'claude-sonnet-5' }), true);
    const result = await proxy.refreshQuotaAll();
    assert.equal(result.targets, 1);
    assert.equal(result.measured, 1);
    assert.deepEqual(admitted, ['native']);
    assert.deepEqual(refreshed, ['native']);
    assert.deepEqual(sent, [{
      url: 'https://api.anthropic.com/v1/messages', authorization: 'Bearer t-native',
    }]);
  } finally {
    proxy.close();
  }
});

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

test('friendly upstream pin forms resolve only an unambiguous live account', () => {
  const am = new AccountManager([
    oauth('me@x.com (Acme)', { accountUuid: 'AAA', orgUuid: 'O1' }),
    oauth('me@x.com (Beta)', { accountUuid: 'AAA', orgUuid: 'O2' }),
    oauth('other@x.com', { accountUuid: 'BBB', orgUuid: 'O3' }),
    oauth('0'),
  ], 0.98);
  assert.equal(resolveAccountPin(am, 'BbB'), am.accounts[2]);
  assert.equal(resolveAccountPin(am, 'O2'), am.accounts[1]);
  assert.equal(resolveAccountPin(am, 'me@x.com (Beta)'), am.accounts[1]);
  assert.equal(resolveAccountPin(am, 'other@x.com'), am.accounts[2]);
  assert.equal(resolveAccountPin(am, 'AAA/O2'), am.accounts[1]);
  assert.equal(resolveAccountPin(am, 'AAA/O1'), am.accounts[0]);
  assert.equal(resolveAccountPin(am, 'AAA'), null, 'shared person UUID is ambiguous');
  assert.equal(resolveAccountPin(am, 'me@x.com'), null, 'shared email is ambiguous');
  assert.equal(resolveAccountPin(am, '0'), null, 'numeric names cannot alias an array index');
  assert.equal(resolveAccountPin(am, ''), null);
});

// ── end-to-end pin routing (integration) ─────────────────────────────────────

// Stand up a mock upstream that records the path and Authorization it received,
// so we can prove which account a pinned request was routed to and that the
// /tc-acct/<pin> prefix was stripped before forwarding.
async function withProxy(run, accounts = [oauth('alpha'), oauth('beta')]) {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push({ path: req.url, auth: req.headers.authorization, key: req.headers['x-api-key'] });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  const upstreamPort = await listen(upstream);

  const am = new AccountManager(accounts, 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    activeWarmup: false,
  });
  const proxyPort = await listen(proxy);
  try {
    return await run({ proxyPort, seen, am });
  } finally {
    proxy.close();
    upstream.close();
  }
}

const post = (url, signal) => fetch(url, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ model: 'x', messages: [] }),
  signal,
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
    const res = await post(`http://127.0.0.1:${proxyPort}/tc-acct/1/v1/messages`);
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

test('a canonical Anthropic subscription pin cannot inject its token into Codex', async () => {
  await withProxy(async ({ proxyPort, seen, am }) => {
    const res = await post(`http://127.0.0.1:${proxyPort}/tc-acct/${pin(am.accounts[0])}/backend-api/codex/responses`);
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.error.message, /cannot serve/);
    assert.equal(seen.length, 0);
    assert.equal(am.accounts[0].inflight, 0);
  });
});

test('the OAuth identity relay ignores a canonical inference pin and strips the proxy key', async () => {
  await withProxy(async ({ proxyPort, seen, am }) => {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/tc-acct/${pin(am.accounts[1])}/api/oauth/profile`, {
      headers: { authorization: 'Bearer client-token', 'x-api-key': 'k' },
    });
    await res.text();
    assert.equal(res.status, 200);
    assert.equal(seen[0].auth, 'Bearer client-token');
    assert.equal(seen[0].key, undefined);
    assert.equal(seen[0].path, '/api/oauth/profile');
    assert.ok(am.accounts.every(a => a.inflight === 0));
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

// The escaping of a `/tc-acct/` segment is the CLIENT's, so a malformed one is
// an ordinary bad request rather than something the proxy should choke on:
// decodeURIComponent throws URIError on '%', '%zz' and a truncated '%E0%A4'.
// The request is raced against a timer, so "never answered" is a failed
// assertion rather than a run that never finishes.
async function postWithin(url, ms = 4000) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms);
  try {
    const res = await post(url, ac.signal);
    await res.text();
    return res.status;
  } catch (err) {
    if (err.name === 'AbortError') return 'HUNG';
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

test('a /tc-acct/ pin with a malformed escape is answered, not left hanging', async () => {
  await withProxy(async ({ proxyPort, seen }) => {
    for (const pin of ['%', '%zz', '%E0%A4']) {
      assert.equal(await postWithin(`http://127.0.0.1:${proxyPort}/tc-acct/${pin}/v1/messages`), 404,
        `a pin of "${pin}" left the client waiting on a request nobody will answer`);
    }
    // A well-formed but unresolvable pin is the same answer, which is the point:
    // an undecodable pin is an unusable pin, not an internal error.
    assert.equal(await postWithin(`http://127.0.0.1:${proxyPort}/tc-acct/%67%68/v1/messages`), 404);
    assert.equal(seen.length, 0, 'an unresolvable pin reached upstream');
  });
});
