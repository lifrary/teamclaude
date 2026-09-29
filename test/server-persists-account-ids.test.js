import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnServer } from '../test-helpers/spawn-server.js';

// The server persists refreshed tokens by re-reading the config and finding the
// account's row by entry id — and by id only, since identity is not one-to-one
// (#203). A config written before ids existed has them in memory only, and the
// re-read would mint a different set, so nothing would pair until a restart and
// refreshed tokens would never reach disk. Startup therefore writes the ids it
// minted, once, so the in-memory ids are the on-disk ids.

// Starts the server on `config`, stops it once it is up, and returns what the
// file holds afterwards — plus the exact bytes the harness wrote before the
// server ran, which is the reference for "the server did not touch the file".
async function runServerOnce(config, dir) {
  const srv = await spawnServer({ config: () => config, dir });
  try {
    return { onDisk: await readFile(srv.configPath, 'utf8'), written: JSON.stringify(srv.config), dir: srv.dir };
  } finally {
    await srv.stop();
  }
}

test('a server started on a config without entry ids writes them to disk, once', async () => {
  const first = await runServerOnce({
    proxy: { apiKey: 'tc-test' },
    upstream: 'https://api.anthropic.com',
    upstreamProxy: false,
    accounts: [
      { name: 'a', type: 'apikey', apiKey: 'k1' },
      { name: 'b', type: 'apikey', apiKey: 'k2', id: 'dup' },
      { name: 'c', type: 'apikey', apiKey: 'k3', id: 'dup' }, // a hand-copied section: re-minted
    ],
  });
  const saved = JSON.parse(first.onDisk);
  const ids = saved.accounts.map(a => a.id);
  assert.ok(ids.every(id => typeof id === 'string' && id.length > 0), `every row carries an id: ${JSON.stringify(ids)}`);
  assert.equal(new Set(ids).size, ids.length, 'and no two rows share one');
  assert.deepEqual(saved.accounts.map(a => a.name), ['a', 'b', 'c'], 'nothing else about the rows changed');

  // A file that already carries a complete set is left exactly as it is: the
  // ids must be stable, or the next start would break every pairing again.
  // The harness writes the file compact and the server's save is indented, so
  // the bytes still reading as written is the witness for "no rewrite".
  const second = await runServerOnce(saved, first.dir);
  assert.deepEqual(JSON.parse(second.onDisk).accounts.map(a => a.id), ids);
  assert.equal(second.onDisk, second.written, 'no rewrite when the ids are already on disk');
});
