import { it } from 'node:test';
import * as assert from 'node:assert/strict';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { checkOSV } from '../../lib/depsdev';
import { options } from '../options';

it('handles malformed OSV JSON through the warning path', async (t) => {
  t.mock.method(
    https,
    'request',
    (url: string, callback: (response: EventEmitter & { statusCode: number }) => void) => {
      const req = new EventEmitter();
      return Object.assign(req, {
        end() {
          setImmediate(() => {
            const res = Object.assign(new EventEmitter(), { statusCode: 200 });
            callback(res);
            res.emit('data', Buffer.from('{'));
            res.emit('end');
          });
        },
      });
    },
  );
  let warning = '';
  const config = {
    ...options,
    log: {
      ...options.log,
      warn(message: string) {
        warning = message;
      },
    },
  };

  const result = await checkOSV('sample', '1', config);

  assert.deepEqual(result, []);
  assert.match(warning, /Invalid JSON from https:\/\/api\.deps\.dev\//);
});
