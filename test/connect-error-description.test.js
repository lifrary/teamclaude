import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeErrorChain } from '../src/server.js';

// Node's happy-eyeballs dialer reports a connect where every address failed as
// an AggregateError whose own message is EMPTY; the per-address reasons are in
// .errors. api.anthropic.com is multi-address, so this shape is reachable in
// production, and a describer that only walks .cause prints "AggregateError: "
// with nothing after it — which is what the operator has to act on.
test('a multi-address connect failure names the per-address reasons', () => {
  const agg = new AggregateError([
    new Error('connect ECONNREFUSED 1.2.3.4:443'),
    new Error('connect ENETUNREACH 2606::1:443'),
  ]);
  const wrapped = new TypeError('fetch failed', { cause: agg });

  const out = describeErrorChain(wrapped);
  assert.match(out, /ECONNREFUSED 1\.2\.3\.4:443/);
  assert.match(out, /ENETUNREACH 2606::1:443/);
  assert.doesNotMatch(out, /AggregateError:\s*$/, 'must not end on an empty AggregateError');
});

// The other half of the union: a plain wrapped cause still reports its name and
// its code, which is what the transient classifier keys on.
test('a single-cause transport failure keeps its name and code', () => {
  const cause = Object.assign(new Error('Request body length does not match content-length header'), {
    name: 'RequestContentLengthMismatchError',
    code: 'UND_ERR_REQ_CONTENT_LENGTH_MISMATCH',
  });
  const out = describeErrorChain(new TypeError('fetch failed', { cause }));

  assert.match(out, /TypeError: fetch failed/);
  assert.match(out, /RequestContentLengthMismatchError/);
  assert.match(out, /code=UND_ERR_REQ_CONTENT_LENGTH_MISMATCH/);
});

test('an error carrying both a message and aggregated reasons keeps both', () => {
  const agg = Object.assign(new AggregateError([new Error('reason-a')], 'outer said this'), { code: 'EAGG' });
  const out = describeErrorChain(agg);
  assert.match(out, /outer said this/);
  assert.match(out, /reason-a/);
  assert.match(out, /code=EAGG/);
});
