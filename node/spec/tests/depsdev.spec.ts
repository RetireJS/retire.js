import { it } from 'node:test';
import * as assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import * as http from '../../lib/http';
import { checkOSV } from '../../lib/depsdev';
import { options } from '../options';

it('handles malformed OSV JSON through the warning path', async (t) => {
  t.mock.method(http, 'get', async () => {
    const res = Object.assign(new PassThrough(), { statusCode: 200 });
    res.end('{');
    return res;
  });
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
