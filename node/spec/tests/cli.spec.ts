import { it } from 'node:test';
import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { EventEmitter } from 'node:events';
import { setTimeout } from 'node:timers/promises';
import * as repo from '../../lib/repo';
import * as depsdev from '../../lib/depsdev';
import * as resolve from '../../lib/resolve';
import * as reporting from '../../lib/reporting';
import { Options } from '../../lib/types';

const root = path.resolve(__dirname, '../..');

it('terminates invalid CLI input without scanning or a stack trace', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-cli-'));
  try {
    const repo = path.join(dir, 'repo.json');
    fs.writeFileSync(repo, '{}');
    const invalidIgnore = path.join(dir, 'invalid.json');
    fs.writeFileSync(invalidIgnore, '{');
    for (const flags of [
      ['--severity', 'invalid'],
      ['--severity', 'toString'],
      ['--severity', 'constructor'],
      ['--severity', '__proto__'],
      ['--severity', '0'],
      ['--severity', ''],
      ['--cacert', path.join(dir, 'missing')],
      ['--ignorefile', path.join(dir, 'missing')],
      ['--ignorefile', invalidIgnore],
    ]) {
      const result = spawnSync(process.execPath, ['lib/cli.js', '--jsrepo', repo, '--path', dir, ...flags], {
        cwd: root,
        encoding: 'utf8',
      });
      assert.equal(result.status, 1);
      assert.match(result.stdout + result.stderr, /Error:/);
      assert.doesNotMatch(result.stdout + result.stderr, /ReferenceError|at Object|Exception caught/);

      const output = path.join(dir, 'report.json');
      const reportResult = spawnSync(
        process.execPath,
        ['lib/cli.js', '--jsrepo', repo, '--path', dir, '--outputformat', 'json', '--outputpath', output, ...flags],
        { cwd: root, encoding: 'utf8' },
      );
      assert.equal(reportResult.status, 1, reportResult.stdout + reportResult.stderr);
      const report = JSON.parse(fs.readFileSync(output, 'utf8'));
      assert.equal(report.errors.length, 1);
      assert.deepEqual(report.data, []);
    }
    const result = spawnSync(process.execPath, ['lib/cli.js', '--jsrepo', repo, '--path', path.join(dir, 'missing')], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(result.status, 1, result.stdout + result.stderr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

it('accepts every severity level and applies its exit-code threshold', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-severity-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const repo = path.join(dir, 'repo.json');
  fs.writeFileSync(
    repo,
    JSON.stringify({
      sample: {
        extractors: { filename: ['sample-(§§version§§)\\.js'] },
        vulnerabilities: [
          {
            below: '2.0.0',
            severity: 'high',
            cwe: ['CWE-79'],
            identifiers: { CVE: ['CVE-2026-1234'] },
            info: ['https://example.com/advisory'],
          },
        ],
      },
    }),
  );
  fs.writeFileSync(path.join(dir, 'sample-1.0.js'), '');

  for (const [severity, exitCode] of [
    ['none', 13],
    ['low', 13],
    ['medium', 13],
    ['high', 13],
    ['critical', 0],
  ] as const) {
    const result = spawnSync(
      process.execPath,
      ['lib/cli.js', '--jsrepo', repo, '--path', dir, '--severity', severity],
      {
        cwd: root,
        encoding: 'utf8',
      },
    );
    assert.equal(result.status, exitCode, result.stdout + result.stderr);
  }
});

it(
  'waits for OSV findings before CLI report closure and passes insecure to repository loading',
  { timeout: 5000 },
  async (t) => {
    const argv = process.argv;
    const exitCode = process.exitCode;
    t.after(() => {
      process.argv = argv;
      process.exitCode = exitCode;
    });
    t.mock.method(repo, 'loadrepositoryFromFile', async (file: string, options: Options) => {
      assert.equal(options.insecure, true);
      return { sample: { extractors: { filename: ['sample-([0-9.]+)[.]js'] }, vulnerabilities: [] } };
    });
    t.mock.method(depsdev, 'checkOSV', async () => {
      await setTimeout(30);
      return [{ below: '2', severity: 'high', cwe: [], identifiers: {}, info: [] }];
    });
    t.mock.method(resolve, 'scanJsFiles', () => {
      const finder = new EventEmitter();
      setImmediate(() => {
        finder.emit('jsfile', 'sample-1.0.js');
        finder.emit('end');
      });
      return finder;
    });
    let findings = 0;
    const errors: string[] = [];
    const closed = new Promise<void>((done) => {
      t.mock.method(reporting, 'open', () => ({
        info() {},
        debug() {},
        warn() {},
        error(message: string) {
          errors.push(message);
        },
        logDependency() {},
        logVulnerableDependency() {
          findings++;
        },
        close: done,
      }));
    });
    process.argv = [process.execPath, 'cli', '--jsrepo', 'fixture', '--includeOsv', '--insecure'];

    await import('../../lib/cli');
    await closed;

    assert.deepEqual(errors, []);
    assert.equal(findings, 1);
    assert.equal(process.exitCode, 13);
  },
);
