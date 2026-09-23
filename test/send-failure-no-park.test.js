import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';
import { setUpstreamProxy, resolveUpstreamProxy, resetUpstreamProxy } from '../src/upstream-proxy.js';

// A thrown send failure says nothing about the account's credentials: a bad
// credential comes back as a 401 response, never as a throw. Parking the account
// in 'error' for it took healthy accounts out of rotation until a restart. On
// 2026-09-23 five of ten accounts were parked within seconds of a lid-close
// sleep and a Wi-Fi switch, and each still answered a direct request on the
// very token the proxy held. A reply that is not HTTP stands in for that class
// here: it throws HPE_INVALID_CONSTANT, which is not a transient code, so it
// takes the same branch an ECONNABORTED does.

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

async function post(port) {
  const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'claude-opus-5', messages: [] }),
  });
  return `${res.status} ${await res.text()}`;
}

test('a non-transient send failure fails over without parking the account', async () => {
  let brokenHits = 0;
  const broken = net.createServer(socket => { brokenHits += 1; socket.end('NOT-HTTP\r\n\r\n'); });
  let goodHits = 0;
  const good = http.createServer((req, res) => {
    goodHits += 1;
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
  });
  const brokenPort = await listen(broken);
  const goodPort = await listen(good);

  const am = new AccountManager([
    { name: 'a', type: 'apikey', apiKey: 'k-a' },
    { name: 'b', type: 'apikey', apiKey: 'k-b' },
  ], 0.98);
  am.accounts[0].upstream = `http://127.0.0.1:${brokenPort}`;
  am.accounts[1].upstream = `http://127.0.0.1:${goodPort}`;

  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: false }, {}));
  const proxy = createProxyServer(am, { activeWarmup: false, proxy: {}, upstream: `http://127.0.0.1:${goodPort}` });
  const port = await listen(proxy);
  const realErr = console.error;
  const realLog = console.log;
  console.error = () => {};
  console.log = () => {};
  let outcome;
  try {
    outcome = await post(port);
  } finally {
    console.error = realErr;
    console.log = realLog;
    resetUpstreamProxy();
    proxy.close();
    broken.close();
    good.close();
  }

  assert.equal(brokenHits, 1,
    `the request never reached the broken account, so nothing here was measured (outcome: ${outcome})`);
  assert.match(outcome, /^200 /, 'the request did not fail over to the healthy account');
  assert.equal(goodHits, 1);
  assert.equal(am.accounts[0].status, 'active',
    'a transport failure parked the account in error, out of rotation until a restart');
});
