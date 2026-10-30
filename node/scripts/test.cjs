const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function specs(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(dir, entry.name);
    return entry.isDirectory() ? specs(file) : file.endsWith('.spec.ts') ? [file] : [];
  });
}

const result = spawnSync(process.execPath, ['--require', 'ts-node/register', '--test', ...specs('spec/tests')], {
  stdio: 'inherit',
  env: { ...process.env, TS_NODE_PROJECT: 'tsconfig.spec.json' },
});
if (result.error) console.error(result.error);
process.exitCode = result.status ?? 1;
