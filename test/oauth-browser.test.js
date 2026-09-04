import test from 'node:test';
import assert from 'node:assert/strict';
import { getBrowserLaunchSpec } from '../src/oauth.js';

const url = 'https://example.test/oauth?state=a%2Bb&code=c%2Fd&prompt=consent';

test('builds argument-safe browser launch commands for each platform', () => {
  assert.deepEqual(getBrowserLaunchSpec(url, 'darwin'), {
    command: 'open',
    args: [url],
  });
  assert.deepEqual(getBrowserLaunchSpec(url, 'linux'), {
    command: 'xdg-open',
    args: [url],
  });
  assert.deepEqual(getBrowserLaunchSpec(url, 'win32'), {
    command: 'rundll32.exe',
    args: ['url.dll,FileProtocolHandler', url],
  });
});
