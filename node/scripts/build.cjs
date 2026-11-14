const fs = require('node:fs');

fs.chmodSync('lib/cli.js', 0o755);
fs.copyFileSync('src/retire.d.ts', 'lib/retire.d.ts');
fs.copyFileSync('../LICENSE.md', 'LICENSE.md');
