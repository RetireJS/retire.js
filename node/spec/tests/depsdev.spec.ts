import { it } from 'node:test';
import { run } from '../run-script';

it('handles malformed OSV JSON through the warning path', () => {
  run(`
    const assert = require('node:assert/strict');
    const https = require('node:https');
    const { EventEmitter } = require('node:events');
    https.request = (url, callback) => {
      const req = new EventEmitter();
      req.end = () => setImmediate(() => {
        const res = new EventEmitter(); res.statusCode = 200; callback(res);
        res.emit('data', Buffer.from('{')); res.emit('end');
      });
      return req;
    };
    let warning = '';
    require('./lib/depsdev').checkOSV('sample', '1', { log: { debug() {}, warn(s) { warning = s; } } }).then(result => {
      assert.deepEqual(result, []);
      assert.match(warning, /api.deps.dev/);
    }).catch(e => { console.error(e); process.exitCode = 1; });
  `);
});
