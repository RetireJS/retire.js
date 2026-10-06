import { it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';
import * as repo from '../../lib/repo';
import { options } from '../options';

it('rejects malformed local and remote repositories with source context', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-json-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'broken.json');
  fs.writeFileSync(file, '{');

  await assert.rejects(repo.loadrepositoryFromFile(file, options), (error) => String(error).includes(file));

  const server = http.createServer((req, res) => res.end('{'));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + (server.address() as AddressInfo).port + '/broken.json';

  await assert.rejects(repo.loadrepository(url, options), (error) => String(error).includes(url));
});
