import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';
import { OutsideSpendTracker, OUTSIDE_SPEND_SETTLE_MS } from '../src/outside-spend.js';
import { outsideSpendText } from '../src/status-renderer.js';
import { renderDashboardHtml } from '../src/dashboard.js';

// Outside spend (#475): a rise between two fresh readings with nothing served by
// this proxy in between is spend from elsewhere; a rise while we served is
// unattributable and not counted. Three explicit states, never 0% for "no answer".

const DAY = 24 * 3600_000;
const RESET = Date.now() + 5 * DAY;

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

function probe(am, utilization, extra = {}) {
  am.applyUsageData(0, { sevenDay: { utilization, resetAt: RESET }, ...extra });
}

// Move the end of the last request past the settle time, as if it ended long ago.
function settled(am, i = 0) {
  am.accounts[i].activityEndedAt = Date.now() - OUTSIDE_SPEND_SETTLE_MS - 1;
}

function weekly(am) {
  return am.getStatus().accounts[0].quota.outsideSpend.unified7d;
}

// ── the tracker on its own ────────────────────────────────────────────────

test('one reading is not an answer; an idle rise to the next one is outside spend', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7d', 0.30, RESET, 'seq:4', 1_000);
  assert.deepEqual(t.view(0, 'unified7d', 1_000), { share: null, state: 'not_observed', since: new Date(1_000).toISOString() });
  t.observe(0, 'unified7d', 0.34, RESET, 'seq:4', 2_000);
  const v = t.view(0, 'unified7d', 2_000);
  assert.equal(v.state, 'measured');
  assert.ok(Math.abs(v.share - 0.04) < 1e-9, `share ${v.share}`);
});

test('a rise while the proxy served is not counted, and alone it is not measurable', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7d', 0.30, RESET, 'seq:4', 1_000);
  t.observe(0, 'unified7d', 0.40, RESET, 'seq:5', 2_000);
  assert.deepEqual(t.view(0, 'unified7d', 2_000), { share: null, state: 'not_measurable', since: new Date(1_000).toISOString() });
});

test('only the idle intervals add up, and a flat idle interval is a measured zero', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7d', 0.30, RESET, 'seq:1', 1_000);
  t.observe(0, 'unified7d', 0.30, RESET, 'seq:1', 2_000);   // idle, flat
  assert.deepEqual(t.view(0, 'unified7d', 2_000).share, 0);
  t.observe(0, 'unified7d', 0.50, RESET, 'seq:2', 3_000);   // served: +0.20 not counted
  t.observe(0, 'unified7d', 0.53, RESET, 'seq:2', 4_000);   // idle: +0.03 counted
  const v = t.view(0, 'unified7d', 4_000);
  assert.equal(v.state, 'measured');
  assert.ok(Math.abs(v.share - 0.03) < 1e-9, `share ${v.share}`);
});

test('a small drop is noise, never negative spend; a large drop starts a new window', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7d', 0.30, null, 'seq:1', 1_000);
  t.observe(0, 'unified7d', 0.34, null, 'seq:1', 2_000);
  t.observe(0, 'unified7d', 0.33, null, 'seq:1', 3_000);   // -0.01: rebaseline only
  assert.ok(Math.abs(t.view(0, 'unified7d', 3_000).share - 0.04) < 1e-9);
  t.observe(0, 'unified7d', 0.02, null, 'seq:1', 4_000);   // reset: sum starts over
  assert.equal(t.view(0, 'unified7d', 4_000).state, 'not_observed');
  assert.equal(t.view(0, 'unified7d', 4_000).since, new Date(4_000).toISOString());
});

test('a wobbling reading never counts the same spend twice', () => {
  const t = new OutsideSpendTracker();
  let at = 1_000;
  for (const u of [0.30, 0.31, 0.30, 0.31, 0.30, 0.31, 0.30, 0.31]) t.observe(0, 'unified7d', u, RESET, 'seq:1', at += 1_000);
  const v = t.view(0, 'unified7d', at);
  assert.equal(v.state, 'measured');
  assert.ok(Math.abs(v.share - 0.01) < 1e-9, `net rise is 0.01, got ${v.share}`);
});

test('a served rise raises the mark, so an idle bounce back up is not counted', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7d', 0.30, RESET, 'seq:1', 1_000);
  t.observe(0, 'unified7d', 0.40, RESET, 'seq:2', 2_000);   // our spend
  t.observe(0, 'unified7d', 0.38, RESET, 'seq:2', 3_000);   // noise, idle
  t.observe(0, 'unified7d', 0.41, RESET, 'seq:2', 4_000);   // idle: only 0.01 is new
  assert.ok(Math.abs(t.view(0, 'unified7d', 4_000).share - 0.01) < 1e-9);
});

test('an earlier reset from a disagreeing source does not restart the window', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7dFable', 0.10, RESET, 'seq:1', 1_000);
  t.observe(0, 'unified7dFable', 0.15, RESET - 2 * DAY, 'seq:1', 2_000);
  const v = t.view(0, 'unified7dFable', 2_000);
  assert.equal(v.state, 'measured');
  assert.ok(Math.abs(v.share - 0.05) < 1e-9);
});

test('a moved reset stamp starts a new window; a passed one stops reporting the old sum', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7d', 0.30, 10_000, 'seq:1', 1_000);
  t.observe(0, 'unified7d', 0.35, 10_000, 'seq:1', 2_000);
  assert.equal(t.view(0, 'unified7d', 2_000).state, 'measured');
  assert.equal(t.view(0, 'unified7d', 10_000).state, 'not_observed', 'the window is over');
  t.observe(0, 'unified7d', 0.36, 10_000 + 7 * DAY, 'seq:1', 3_000);
  assert.equal(t.view(0, 'unified7d', 3_000).state, 'not_observed', 'new window, first reading');
});

test('the windows survive a restart, but the interval across it is never outside', () => {
  const t1 = new OutsideSpendTracker();
  t1.observe(0, 'unified7d', 0.30, RESET, 'seq:1', 1_000);
  t1.observe(0, 'unified7d', 0.34, RESET, 'seq:1', 2_000);
  const saved = JSON.parse(JSON.stringify(t1.export(0)));
  assert.equal(saved.unified7d.lastActivity, undefined, 'the process-local stamp is not saved');

  const t2 = new OutsideSpendTracker();
  t2.restore(0, saved, 3_000);
  // Same stamp value as before the restart: it must still not count as idle.
  t2.observe(0, 'unified7d', 0.50, RESET, 'seq:1', 4_000);
  const v = t2.view(0, 'unified7d', 4_000);
  assert.equal(v.state, 'measured');
  assert.ok(Math.abs(v.share - 0.04) < 1e-9, `share ${v.share}`);
});

test('restore drops garbage and windows that are already over', () => {
  const t = new OutsideSpendTracker();
  t.restore(0, { unified7d: { lastU: 'x' }, unified7dFable: { lastU: 0.1, lastAt: 1, since: 1, resetAt: 5 }, '': {} }, 10);
  assert.deepEqual(t.viewAll(0, 10), {});
  t.restore(0, null);
  t.restore(0, [1, 2]);
  assert.deepEqual(t.viewAll(0, 10), {});
});

test('remapAccounts follows a reindexing and drops removed accounts', () => {
  const t = new OutsideSpendTracker();
  t.observe(0, 'unified7d', 0.1, RESET, 'seq:0', 1);
  t.observe(1, 'unified7d', 0.2, RESET, 'seq:0', 1);
  t.remapAccounts(i => (i === 0 ? null : 0));
  assert.deepEqual(Object.keys(t.viewAll(0, 2)), ['unified7d']);
  assert.deepEqual(t.viewAll(1, 2), {});
});

// ── AccountManager: the three fresh-reading paths and the activity stamp ──

test('two probe readings with nothing dispatched between them: measured outside spend', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  probe(am, 0.30);
  assert.equal(weekly(am).state, 'not_observed');
  probe(am, 0.33);
  const v = weekly(am);
  assert.equal(v.state, 'measured');
  assert.ok(Math.abs(v.share - 0.03) < 1e-9, `share ${v.share}`);
});

test('a request the proxy served between two probes makes that interval unattributable', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  probe(am, 0.30);
  am.beginActivity(0);
  am.updateQuota(0, { 'anthropic-ratelimit-unified-7d-utilization': '0.35', 'anthropic-ratelimit-unified-7d-reset': String(Math.floor(RESET / 1000)) });
  am.endActivity(0);
  probe(am, 0.40);
  assert.deepEqual({ share: weekly(am).share, state: weekly(am).state }, { share: null, state: 'not_measurable' });
});

test('a stream still open across an interval keeps it busy, even with no new dispatch', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.beginActivity(0);           // dispatched before the first reading, still streaming
  probe(am, 0.30);
  probe(am, 0.38);               // the stream spent this
  am.endActivity(0);
  settled(am);
  assert.equal(weekly(am).state, 'not_measurable');
  // The stream was open at the 0.38 reading and ended after it, so it may have
  // spent in the next interval too: that one is still the proxy's.
  probe(am, 0.40);
  assert.equal(weekly(am).state, 'not_measurable');
  probe(am, 0.42);               // the first interval with nothing open at either end
  assert.equal(weekly(am).state, 'measured');
  assert.ok(Math.abs(weekly(am).share - 0.02) < 1e-9, `share ${weekly(am).share}`);
});

test('a probe that reports Fable twice (field and scopedWeekly) is one window', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const payload = (uf) => ({
    sevenDay: { utilization: 0.30, resetAt: RESET },
    sevenDayFable: { utilization: uf, resetAt: RESET },
    scopedWeekly: { fable: { utilization: uf, resetAt: RESET } },
    scopedWeeklyListed: true,
  });
  am.applyUsageData(0, payload(0.10));
  am.applyUsageData(0, payload(0.20));
  const o = am.getStatus().accounts[0].quota.outsideSpend;
  assert.deepEqual(Object.keys(o).sort(), ['unified7d', 'unified7dFable']);
  assert.ok(Math.abs(o.unified7dFable.share - 0.10) < 1e-9);
  assert.equal(outsideSpendText(o).split('Fable').length - 1, 1, 'Fable named once');
});

test('a Fable response header carrying the shared reset does not restart the Fable window', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const fableReset = RESET - 3 * DAY;
  const probeF = (u) => am.applyUsageData(0, { sevenDay: { utilization: 0.3, resetAt: RESET }, sevenDayFable: { utilization: u, resetAt: fableReset } });
  probeF(0.10);
  probeF(0.15);                                   // idle: +0.05 outside
  am.beginActivity(0);
  am.updateQuota(0, {
    'anthropic-ratelimit-unified-7d-utilization': '0.3',
    'anthropic-ratelimit-unified-7d-reset': String(Math.floor(RESET / 1000)),
    'anthropic-ratelimit-unified-7d_oi-utilization': '0.2',
  });
  am.endActivity(0);
  const f = am.getStatus().accounts[0].quota.outsideSpend.unified7dFable;
  assert.equal(f.state, 'measured');
  assert.ok(Math.abs(f.share - 0.05) < 1e-9, `kept the sum, got ${f.share}`);
});

test('a reading inside the settle time after a request is never the start of an idle interval', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.beginActivity(0);
  am.endActivity(0);
  probe(am, 0.30);               // our spend may not have landed yet
  probe(am, 0.34);               // ... and lands here
  assert.equal(weekly(am).state, 'not_measurable');
});

test('a Codex usage probe feeds the weekly window too', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.applyCodexUsageData(0, { sevenDay: { utilization: 0.2, resetAt: RESET } });
  am.applyCodexUsageData(0, { sevenDay: { utilization: 0.25, resetAt: RESET } });
  assert.equal(weekly(am).state, 'measured');
  assert.ok(Math.abs(weekly(am).share - 0.05) < 1e-9);
});

test('an upstream family name is made safe before it reaches a terminal', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  am.applyUsageData(0, { scopedWeekly: { 'evil\u001b[2J': { utilization: 0.1, resetAt: RESET } } });
  const keys = Object.keys(am.getStatus().accounts[0].quota.outsideSpend);
  assert.equal(keys.length, 1);
  assert.doesNotMatch(keys[0], /\u001b/);
});

test('family buckets are tracked on their own; the 5h window is not tracked', () => {
  const am = new AccountManager([oauth('a')], 0.98);
  const payload = (u7, uf) => ({
    fiveHour: { utilization: 0.9, resetAt: Date.now() + 3600_000 },
    sevenDay: { utilization: u7, resetAt: RESET },
    sevenDayFable: { utilization: uf, resetAt: RESET },
  });
  am.applyUsageData(0, payload(0.30, 0.10));
  am.applyUsageData(0, payload(0.30, 0.25));
  const o = am.getStatus().accounts[0].quota.outsideSpend;
  assert.deepEqual(Object.keys(o).sort(), ['unified7d', 'unified7dFable']);
  assert.equal(o.unified7d.share, 0);
  assert.ok(Math.abs(o.unified7dFable.share - 0.15) < 1e-9);
});

test('a weekly window the account reports but nobody re-read says not_observed, not 0', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  am.accounts[0].quota.unified7d = 0.5;      // restored from state, never refreshed
  const [a, b] = am.getStatus().accounts;
  assert.deepEqual(a.quota.outsideSpend.unified7d, { share: null, state: 'not_observed', since: null });
  assert.deepEqual(b.quota.outsideSpend, {}, 'no weekly window reported, nothing to say');
});

test('the sums persist through exportQuotaState / restoreQuotaState', () => {
  const am1 = new AccountManager([oauth('a', { accountUuid: 'u1' })], 0.98);
  probe(am1, 0.30);
  probe(am1, 0.36);
  const am2 = new AccountManager([oauth('a', { accountUuid: 'u1' })], 0.98);
  am2.restoreQuotaState(JSON.parse(JSON.stringify(am1.exportQuotaState())));
  assert.equal(weekly(am2).state, 'measured');
  assert.ok(Math.abs(weekly(am2).share - 0.06) < 1e-9);
  probe(am2, 0.50);              // spans the restart: not attributed
  assert.ok(Math.abs(weekly(am2).share - 0.06) < 1e-9);
});

// ── the server marks a forwarded request busy until its body has ended ───

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

async function until(condition) {
  while (!condition()) await new Promise(r => setImmediate(r));
}

test('the proxy holds the account busy from dispatch until the stream ends', async () => {
  let release;
  const gate = new Promise(r => { release = r; });
  let headersSent;
  const sent = new Promise(r => { headersSent = r; });
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', async () => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('event: ping\ndata: {"type":"ping"}\n\n');
      headersSent();
      await gate;
      res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
    });
  });
  const upPort = await listen(upstream);
  const am = new AccountManager([{ name: 'k', type: 'apikey', apiKey: 'k1' }], 0.98);
  const proxy = createProxyServer(am, { proxy: {}, upstream: `http://127.0.0.1:${upPort}` }, {});
  const port = await listen(proxy);
  try {
    const pending = fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-opus-5', messages: [], stream: true }),
    }).then(r => r.text());
    await sent;
    // Wait for the state, not for a delay: the upstream holds the body open
    // until release(), so the dispatched request is seen with the stream open.
    // The runner's own timeout is the bound (test/README.md). Fork: the slot is
    // held until the stream ends (released in the request's finally), not
    // released when the headers arrive.
    await until(() => am.accounts[0].usage.totalRequests === 1);
    assert.equal(am.accounts[0].inFlight, 1, 'the slot is held while the body streams');
    assert.equal(am.accounts[0].activityOpen, 1, 'still busy while the body streams');
    release();
    await pending;
    await until(() => am.accounts[0].activityOpen === 0 && am.accounts[0].inFlight === 0);
    assert.equal(am.accounts[0].activitySeq, 1);
  } finally {
    proxy.close();
    upstream.close();
  }
});

// ── the read-out ──────────────────────────────────────────────────────────

test('outsideSpendText names each window and never shows 0% for "no answer"', () => {
  const since = '2026-10-05T08:00:00.000Z';
  assert.equal(outsideSpendText(null), null);
  assert.equal(outsideSpendText({}), null);
  assert.equal(outsideSpendText({
    'scoped:opus': { share: 0.1, state: 'measured', since },
    unified7dFable: { share: null, state: 'not_measurable', since },
    unified7d: { share: 0.04, state: 'measured', since },
  }), '4.0% of the week went elsewhere · 10.0% of the Opus week went elsewhere · Fable week: not measurable');
  assert.equal(outsideSpendText({ unified7d: { share: 0, state: 'measured', since } }), '0.0% of the week went elsewhere');
  const unknown = outsideSpendText({ unified7d: { share: null, state: 'not_observed', since: null } });
  assert.equal(unknown, 'week: not observed (quota probe off?)');
  assert.doesNotMatch(unknown, /0%/);
});

test('the dashboard page carries the same outsideSpendText', () => {
  assert.ok(renderDashboardHtml().includes(outsideSpendText.toString()));
});
