import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as path from 'node:path';

const root = path.resolve(__dirname, '..');
export function run(script: string) {
  const result = spawnSync(process.execPath, ['-e', script], { cwd: root, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
}
