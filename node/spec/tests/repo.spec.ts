import { it } from 'node:test';
import { run } from '../run-script';

it('rejects malformed local and remote repositories with source context', () => {
  run(`
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const http = require('node:http');
    const repo = require('./lib/repo');
    const options = { nocache: true, log: { info() {}, debug() {} } };
    (async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-json-'));
      const file = path.join(dir, 'broken.json');
      fs.writeFileSync(file, '{');
      const server = http.createServer((req, res) => res.end('{'));
      try {
        await assert.rejects(repo.loadrepositoryFromFile(file, options), e => String(e).includes(file));
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const url = 'http://127.0.0.1:' + server.address().port + '/broken.json';
        await assert.rejects(repo.loadrepository(url, options), e => String(e).includes(url));
      } finally { server.close(); fs.rmSync(dir, { recursive: true, force: true }); }
    })().catch(e => { console.error(e); process.exitCode = 1; });
  `);
});
