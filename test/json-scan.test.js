import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jsonStringEnd, endsInEscape } from '../src/json-scan.js';
import { TopLevelFieldFinder, AdvisorModelFinder, parseRequestStream } from '../src/model.js';
import { AccountUuidPatcher, patchAccountUuid } from '../src/account-uuid-rewrite.js';

const b = (/** @type {string} */ s) => Buffer.from(s, 'latin1');

test('jsonStringEnd stops at the first quote an even run of backslashes precedes', () => {
  assert.equal(jsonStringEnd(b('abc"def'), 0), 3);
  assert.equal(jsonStringEnd(b('a\\"b"'), 0), 4, 'one backslash escapes the quote');
  assert.equal(jsonStringEnd(b('a\\\\"b"'), 0), 3, 'two backslashes escape each other, the quote closes');
  assert.equal(jsonStringEnd(b('a\\\\\\"b"'), 0), 6, 'three: the quote is escaped again');
  assert.equal(jsonStringEnd(b('"'), 0), 0);
  assert.equal(jsonStringEnd(b('no quote here'), 0), -1);
  assert.equal(jsonStringEnd(b('a\\"'), 0), -1, 'an escaped quote is not an end');
  // Backslashes before `from` belong to bytes the caller already stepped through.
  assert.equal(jsonStringEnd(b('\\"x"'), 1), 1);
});

test('endsInEscape reports a chunk that ends on an unpaired backslash', () => {
  assert.equal(endsInEscape(b('abc\\'), 0), true);
  assert.equal(endsInEscape(b('abc\\\\'), 0), false);
  assert.equal(endsInEscape(b('abc\\\\\\'), 0), true);
  assert.equal(endsInEscape(b('abc'), 0), false);
  assert.equal(endsInEscape(b('\\\\'), 1), true, 'counting stops at from');
});

// Every body below hides a decoy inside a string the scanners skip, written so
// that treating one escaped quote as the string's end (or a closing quote as
// escaped) reads the decoy as structure and changes the answer. Feeding each
// body split at every byte puts a chunk boundary right after each backslash,
// which is where the escape has to be carried into the next chunk.
function eachSplit(/** @type {Buffer} */ body, /** @type {(parts: Buffer[]) => void} */ check) {
  check([body]);
  for (let i = 1; i < body.length; i++) check([body.subarray(0, i), body.subarray(i)]);
}

test('TopLevelFieldFinder skips escaped quotes in unread strings at every chunk boundary', () => {
  const body = b(JSON.stringify({ a: 'q"},"model":"DECOY\\', model: 'REAL' }));
  eachSplit(body, (parts) => {
    const finder = new TopLevelFieldFinder('model');
    let value = null;
    for (const part of parts) value = finder.push(part);
    assert.equal(value, 'REAL', `split ${parts[0].length}`);
  });
});

test('parseRequestStream is not fooled by a stream field written inside text', () => {
  const body = b(JSON.stringify({ messages: [{ content: 's"},"stream":true,\\' }], stream: false }));
  assert.equal(parseRequestStream(body), false);
  eachSplit(body, (parts) => {
    const finder = new TopLevelFieldFinder('stream');
    let value = null;
    for (const part of parts) value = finder.push(part);
    assert.equal(value, 'false', `split ${parts[0].length}`);
  });
});

test('AdvisorModelFinder skips an advisor tool quoted in text at every chunk boundary', () => {
  const body = b(JSON.stringify({
    messages: [{ content: 't"},{"type":"advisor_x","model":"DECOY\\"}],"tools":[' }],
    tools: [{ type: 'advisor_20260301', name: 'advisor', model: 'REAL' }],
  }));
  eachSplit(body, (parts) => {
    const finder = new AdvisorModelFinder();
    let value = null;
    for (const part of parts) value = finder.push(part);
    assert.equal(value, 'REAL', `split ${parts[0].length}`);
  });
});

test('AccountUuidPatcher leaves a quoted decoy alone at every chunk boundary', () => {
  const OLD = '4c39e915-eb47-450d-9bf4-4cbbcd049a08';
  const NEW = '11111111-2222-3333-4444-555555555555';
  const body = b(JSON.stringify({
    messages: [{ content: `u"},"metadata":{"user_id":"{\\"account_uuid\\":\\"${OLD}\\"}\\` }],
    metadata: { user_id: JSON.stringify({ device_id: 'd', account_uuid: OLD }) },
  }));
  const oneShot = patchAccountUuid(body, NEW);
  const parsed = JSON.parse(oneShot.toString('latin1'));
  assert.equal(JSON.parse(parsed.metadata.user_id).account_uuid, NEW);
  assert.ok(parsed.messages[0].content.includes(OLD), 'the decoy in text is untouched');
  eachSplit(body, (parts) => {
    const patcher = new AccountUuidPatcher(NEW);
    const out = Buffer.concat(parts.map((part) => Buffer.from(patcher.push(part))));
    assert.deepEqual(out, oneShot, `split ${parts[0].length}`);
  });
});

test('AccountUuidPatcher returns the chunk itself when nothing in it changed', () => {
  const NEW = '11111111-2222-3333-4444-555555555555';
  const patcher = new AccountUuidPatcher(NEW);
  const head = b('{"messages":[{"content":"plenty of text"}],');
  assert.equal(patcher.push(head), head);
});
