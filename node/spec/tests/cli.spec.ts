import { it } from 'node:test';
import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { run } from '../run-script';

const root = path.resolve(__dirname, '../..');

it('terminates invalid CLI input without scanning or a stack trace', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-cli-'));
  try {
    const repo = path.join(dir, 'repo.json');
    fs.writeFileSync(repo, '{}');
    for (const flags of [
      ['--severity', 'invalid'],
      ['--severity', 'toString'],
      ['--cacert', path.join(dir, 'missing')],
      ['--ignorefile', path.join(dir, 'missing')],
    ]) {
      const result = spawnSync(process.execPath, ['lib/cli.js', '--jsrepo', repo, '--path', dir, ...flags], {
        cwd: root,
        encoding: 'utf8',
      });
      assert.equal(result.status, 1);
      assert.match(result.stdout + result.stderr, /Error:/);
      assert.doesNotMatch(result.stdout + result.stderr, /ReferenceError|at Object|Exception caught/);
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

it('waits for OSV findings before CLI report closure and passes insecure to repository loading', () => {
  run(`
    const assert = require('node:assert/strict');
    const { EventEmitter } = require('node:events');
    const repo = { sample: { extractors: { filename: ['sample-([0-9.]+)[.]js'] }, vulnerabilities: [] } };
    require('./lib/repo').loadrepositoryFromFile = async (file, options) => {
      assert.equal(options.insecure, true);
      return repo;
    };
    require('./lib/depsdev').checkOSV = async () => {
      await new Promise(resolve => setTimeout(resolve, 30));
      return [{ below: '2', severity: 'high', cwe: [], identifiers: {}, info: [] }];
    };
    require('./lib/resolve').scanJsFiles = () => {
      const finder = new EventEmitter();
      setImmediate(() => { finder.emit('jsfile', 'sample-1.0.js'); finder.emit('end'); });
      return finder;
    };
    let findings = 0;
    let closed = false;
    require('./lib/reporting').open = () => ({
      info() {}, debug() {}, warn() {}, error(message) { throw Error(message); },
      logDependency() {}, logVulnerableDependency() { findings++; },
      close() {
        assert.equal(findings, 1);
        assert.equal(process.exitCode, 13);
        closed = true;
        process.exitCode = 0;
      }
    });
    process.on('beforeExit', () => assert.equal(closed, true));
    process.argv = [process.execPath, 'cli', '--jsrepo', 'fixture', '--includeOsv', '--insecure'];
    require('./lib/cli');
  `);
});
