import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCrashReporter, installCrashHandlers } from '../src/crash-log.js';
import { getCrashLogPath } from '../src/config.js';

// A sink that records what would have gone to stderr, so a test can assert the
// crash is still reported there even when the file write fails.
function sink() {
  const written = [];
  return { written, write: (s) => written.push(s) };
}

async function withTempDir(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'tc-crash-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('a fatal error is written to the file with its kind and stack, and exits non-zero', async () => {
  await withTempDir(async (dir) => {
    const path = join(dir, 'crash.log');
    const codes = [];
    const report = createCrashReporter(path, { exit: (c) => codes.push(c), log: sink() });

    report('uncaughtException')(new Error('boom'));

    const body = await readFile(path, 'utf-8');
    assert.match(body, /uncaughtException/);
    assert.match(body, /Error: boom/);
    assert.match(body, /at /, 'the stack, not just the message');
    assert.match(body, /\d{4}-\d{2}-\d{2}T/, 'stamped, or it cannot be tied to a restart');
    assert.deepEqual(codes, [1], 'must do what Node would: exit non-zero');
  });
});

// The first crash of a repeating cycle is the one that explains it, so a later
// crash must not overwrite it.
test('a second crash appends rather than replacing the first', async () => {
  await withTempDir(async (dir) => {
    const path = join(dir, 'crash.log');
    const report = createCrashReporter(path, { exit: () => {}, log: sink() });

    report('uncaughtException')(new Error('first'));
    report('unhandledRejection')(new Error('second'));

    const body = await readFile(path, 'utf-8');
    assert.match(body, /first/);
    assert.match(body, /second/);
    assert.ok(body.indexOf('first') < body.indexOf('second'), 'oldest first');
    assert.match(body, /unhandledRejection/, 'the kind distinguishes the two events');
  });
});

test('the file is owner-only: a stack can carry request context', async () => {
  await withTempDir(async (dir) => {
    const path = join(dir, 'crash.log');
    createCrashReporter(path, { exit: () => {}, log: sink() })('uncaughtException')(new Error('x'));
    assert.equal((await stat(path)).mode & 0o777, 0o600);
  });
});

// The reporter exists to make a crash visible. If it could be silenced by its own
// write failing, it would hide exactly the case it was built for.
test('an unwritable path still reports to stderr and still exits non-zero', async () => {
  await withTempDir(async (dir) => {
    const unwritable = join(dir, 'no-such-directory', 'crash.log');
    const codes = [];
    const log = sink();
    const report = createCrashReporter(unwritable, { exit: (c) => codes.push(c), log });

    report('uncaughtException')(new Error('boom'));

    assert.deepEqual(codes, [1], 'a failed write must not swallow the crash');
    assert.match(log.written.join(''), /Error: boom/);
  });
});

test('a thrown non-Error still yields an entry', () => {
  const log = sink();
  createCrashReporter(join(tmpdir(), 'tc-crash-none', 'x.log'), { exit: () => {}, log })('uncaughtException')('just a string');
  assert.match(log.written.join(''), /just a string/);
});

// Registering the real listeners is what makes the module do anything at all;
// they are removed again so they cannot outlive this test and swallow a genuine
// failure elsewhere in the file.
test('installing registers a handler for both fatal events', () => {
  const before = {
    uncaughtException: process.listeners('uncaughtException').slice(),
    unhandledRejection: process.listeners('unhandledRejection').slice(),
  };
  try {
    installCrashHandlers(join(tmpdir(), 'tc-crash-install.log'), { exit: () => {}, log: sink() });
    assert.equal(process.listeners('uncaughtException').length, before.uncaughtException.length + 1);
    assert.equal(process.listeners('unhandledRejection').length, before.unhandledRejection.length + 1);
  } finally {
    for (const event of ['uncaughtException', 'unhandledRejection']) {
      for (const fn of process.listeners(event)) {
        if (!before[event].includes(fn)) process.removeListener(event, fn);
      }
    }
  }
  assert.equal(process.listeners('uncaughtException').length, before.uncaughtException.length);
});

test('the crash log is a sibling of the config, following TEAMCLAUDE_CONFIG', () => {
  const original = process.env.TEAMCLAUDE_CONFIG;
  try {
    process.env.TEAMCLAUDE_CONFIG = '/tmp/somewhere/teamclaude.json';
    assert.equal(getCrashLogPath(), '/tmp/somewhere/teamclaude.crash.log');
    // A config path without the .json extension must still get a distinct file
    // rather than having its own name replaced.
    process.env.TEAMCLAUDE_CONFIG = '/tmp/somewhere/teamclaude';
    assert.equal(getCrashLogPath(), '/tmp/somewhere/teamclaude.crash.log');
  } finally {
    if (original === undefined) delete process.env.TEAMCLAUDE_CONFIG;
    else process.env.TEAMCLAUDE_CONFIG = original;
  }
});
