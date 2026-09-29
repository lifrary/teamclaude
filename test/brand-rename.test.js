import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { envVar, legacyControlUrl } from '../src/brand.js';
import { getConfigPath, getStatePath } from '../src/config.js';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

// Phase 1 of the rename to TeamRouter (issue #72): the new name is accepted
// everywhere the old one is read, while the old one stays what the proxy
// writes. An install that knows nothing of the rename must see no change.

const listen = (s) => new Promise(r => s.listen(0, '127.0.0.1', () => r(s.address().port)));

function request(port, path, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('envVar reads the TEAMROUTER_ spelling first and falls back to TEAMCLAUDE_', () => {
  assert.equal(envVar('CONFIG', {}), undefined);
  assert.equal(envVar('CONFIG', { TEAMCLAUDE_CONFIG: '/old' }), '/old');
  assert.equal(envVar('CONFIG', { TEAMROUTER_CONFIG: '/new' }), '/new');
  assert.equal(envVar('CONFIG', { TEAMROUTER_CONFIG: '/new', TEAMCLAUDE_CONFIG: '/old' }), '/new');
  // Set to the empty string is set: an exported TEAMROUTER_HOST= masks an
  // inherited TEAMCLAUDE_HOST, as it would for a single-spelling variable.
  assert.equal(envVar('HOST', { TEAMROUTER_HOST: '', TEAMCLAUDE_HOST: '0.0.0.0' }), '');
});

test('legacyControlUrl maps the new route prefix onto the old one and nothing else', () => {
  assert.equal(legacyControlUrl('/teamrouter/status'), '/teamclaude/status');
  assert.equal(legacyControlUrl('/teamrouter/mcp/?x=1'), '/teamclaude/mcp/?x=1');
  assert.equal(legacyControlUrl('/teamrouter'), '/teamclaude');
  assert.equal(legacyControlUrl('/teamrouter?x'), '/teamclaude?x');
  // Not the prefix: a longer first segment, the old spelling, ordinary traffic.
  assert.equal(legacyControlUrl('/teamrouterx/status'), null);
  assert.equal(legacyControlUrl('/teamclaude/status'), null);
  assert.equal(legacyControlUrl('/v1/messages'), null);
  assert.equal(legacyControlUrl(undefined), null);
});

test('the config path prefers TEAMROUTER_CONFIG, then a teamrouter.json that exists, then teamclaude.json', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'teamclaude-brand-'));
  const saved = { ...process.env };
  const restore = () => {
    for (const k of ['TEAMROUTER_CONFIG', 'TEAMCLAUDE_CONFIG', 'XDG_CONFIG_HOME']) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
  };
  t.after(async () => { restore(); await rm(dir, { recursive: true, force: true }); });
  delete process.env.TEAMROUTER_CONFIG;
  delete process.env.TEAMCLAUDE_CONFIG;
  process.env.XDG_CONFIG_HOME = dir;

  // Neither file exists: a fresh install keeps today's name.
  assert.equal(getConfigPath(), join(dir, 'teamclaude.json'));
  assert.equal(getStatePath(), join(dir, 'teamclaude.state.json'));

  // The renamed file, once it exists, is the one used; the state file follows.
  await writeFile(join(dir, 'teamrouter.json'), '{}');
  assert.equal(getConfigPath(), join(dir, 'teamrouter.json'));
  assert.equal(getStatePath(), join(dir, 'teamrouter.state.json'));

  // Either variable wins over both files; the new spelling over the old.
  process.env.TEAMCLAUDE_CONFIG = '/explicit/old.json';
  assert.equal(getConfigPath(), '/explicit/old.json');
  process.env.TEAMROUTER_CONFIG = '/explicit/new.json';
  assert.equal(getConfigPath(), '/explicit/new.json');
});

test('the control plane answers under /teamrouter/ exactly as under /teamclaude/', async () => {
  let upstreamHits = 0;
  const upstream = http.createServer((req, res) => { upstreamHits++; res.writeHead(404); res.end('{}'); });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([{ name: 'a', type: 'apikey', apiKey: 'k' }], 0.98);
  const proxy = createProxyServer(am, { proxy: {}, upstream: `http://127.0.0.1:${upstreamPort}` });
  const port = await listen(proxy);
  try {
    const renamed = await request(port, '/teamrouter/status');
    const legacy = await request(port, '/teamclaude/status');
    assert.equal(renamed.status, 200);
    assert.deepEqual(Object.keys(JSON.parse(renamed.body)).sort(), Object.keys(JSON.parse(legacy.body)).sort());

    assert.equal((await request(port, '/teamrouter/dashboard')).status, 200);
    assert.equal((await request(port, '/teamrouter/quota')).status, 200);

    // A mutation from a web page is refused under the new prefix too.
    const csrf = await request(port, '/teamrouter/reload', { method: 'POST', headers: { origin: 'https://evil.example' } });
    assert.equal(csrf.status, 403);
    assert.match(JSON.parse(csrf.body).error, /cross-origin/);

    // An unclaimed path under the new prefix, in either spelling, is a local
    // 404 and never goes upstream under a fleet credential (#420).
    for (const path of ['/teamrouter/reload', '/teamrouter/statuss', '/teamrouter', '/teamrouter/', '/%74eamrouter/reload']) {
      const { status, body } = await request(port, path);
      assert.equal(status, 404, path);
      assert.match(JSON.parse(body).error, /unknown teamclaude control route/, path);
    }
    assert.equal(upstreamHits, 0, 'nothing was forwarded');

    // A first segment that merely starts with the name is not the prefix.
    await request(port, '/teamrouterx/status');
    assert.equal(upstreamHits, 1);
  } finally {
    proxy.closeAllConnections?.(); proxy.close();
    upstream.closeAllConnections?.(); upstream.close();
  }
});
