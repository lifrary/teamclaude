import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

// The proxy rewrites a request body in two independent places: sanitizeToolPairs
// (orphaned tool_use / tool_result pruning, applied while the request context is
// built) and the model rewrite inside forwardRequest. Whatever it forwards, the
// content-length it declares must describe the bytes it actually sends. undici
// enforces that and aborts a disagreeing request with
// UND_ERR_REQ_CONTENT_LENGTH_MISMATCH, which the proxy could only report as a
// bare TypeError("fetch failed") and hand Claude Code as a 503.
async function forwardThrough(payload, { modelMap } = {}) {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    let bytes = 0;
    req.on('data', c => { bytes += c.length; });
    req.on('end', () => {
      seen.push({ declared: Number(req.headers['content-length']), received: bytes });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  const upstreamPort = await listen(upstream);

  const account = {
    name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r',
    expiresAt: Date.now() + 3600_000,
  };
  if (modelMap) account.modelMap = modelMap;
  const am = new AccountManager([account], 0.98);
  const proxy = createProxyServer(am, {
    proxy: { apiKey: 'k' },
    upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const proxyPort = await listen(proxy);

  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    await res.text();
    return { status: res.status, seen };
  } finally {
    proxy.close();
    upstream.close();
  }
}

// An orphaned tool_use (no matching tool_result) is what a long agentic session
// accumulates after an interrupted tool call. sanitizeToolPairs prunes it, which
// SHRINKS the body — while the client's own content-length still described the
// unpruned bytes. Because the pruned buffer is what forwardRequest then treats as
// "the body", a guard that only refreshed content-length when a LATER rewrite
// changed the buffer left the stale client length in place, and every turn of
// that session died the same way: the orphan lives on in the context, so the
// failure repeats until the session is abandoned.
test('a pruned orphan tool_use does not leave a stale client content-length', async () => {
  const { status, seen } = await forwardThrough({
    model: 'x',
    messages: [
      { role: 'user', content: 'hello' },
      {
        role: 'assistant',
        content: [
          { type: 'text', text: 'calling a tool' },
          { type: 'tool_use', id: 'toolu_orphan_with_a_long_id', name: 'Bash', input: { command: 'echo padding to make the pruned bytes obvious' } },
        ],
      },
      { role: 'user', content: 'never mind' },
    ],
  });

  assert.equal(status, 200, 'proxy must not turn its own body pruning into a 503');
  assert.equal(seen.length, 1, 'upstream must have received exactly one request');
  assert.equal(
    seen[0].declared, seen[0].received,
    'forwarded content-length must describe the bytes the proxy actually sent',
  );
});

test('a model rewrite that grows the body keeps content-length in step', async () => {
  const { status, seen } = await forwardThrough(
    { model: 'short', messages: [{ role: 'user', content: 'hi' }] },
    { modelMap: { short: 'a-considerably-longer-model-identifier' } },
  );
  assert.equal(status, 200);
  assert.equal(seen[0].declared, seen[0].received);
});
