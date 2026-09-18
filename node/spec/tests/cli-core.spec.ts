import { it } from 'node:test';
import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { evaluateLicense } from '../../lib/license';

const root = path.resolve(__dirname, '../..');
function run(script: string) {
  const result = spawnSync(process.execPath, ['-e', script], { cwd: root, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
}

it('excludes the upper license boundary', () => {
  assert.deepEqual(evaluateLicense(['MIT >=0 <2.0.0', 'BSD-3-Clause >=2.0.0'], '2.0.0'), ['BSD-3-Clause']);
});

it('preserves distinct Bootstrap CVEs sharing an issue while removing repeated advisories', () => {
  run(`
    const assert = require('node:assert/strict');
    const retire = require('./lib/retire');
    const repo = JSON.parse(retire.replaceVersion(JSON.stringify(require('../repository/jsrepository-v6.json'))));
    const vulnerabilities = retire.check('bootstrap', '4.0.0', repo)[0].vulnerabilities;
    require('./lib/depsdev').checkOSV = async () => vulnerabilities.concat(vulnerabilities);
    const scanner = require('./lib/scanner');
    let findings = 0;
    scanner.on('vulnerable-dependency-found', finding => {
      findings++;
      const actual = finding.results[0].vulnerabilities;
      assert.equal(actual.length, 4);
      assert.deepEqual(actual.flatMap(v => v.identifiers.CVE).sort(), [
        'CVE-2018-14040', 'CVE-2018-14041', 'CVE-2018-14042', 'CVE-2019-8331'
      ]);
    });
    (async () => {
      await scanner.scanJsFile('bootstrap-4.0.0.js', repo, { includeOsv: true });
      await scanner.scanJsFile('bootstrap-4.0.0.js', repo, { includeOsv: true });
      assert.equal(findings, 2);
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `);
});

it('keeps fallback identifier namespaces separate and prefers canonical identifiers', () => {
  run(`
    const assert = require('node:assert/strict');
    const identifiers = [
      { issue: '123' }, { bug: '123' }, { CVE: ['CVE-2026-1234'], issue: '123' },
      { githubID: 'GHSA-abcd-1234-abcd', bug: '123' }
    ];
    const vulnerabilities = identifiers.map(identifiers => ({ below: '2', severity: 'high', cwe: [], identifiers, info: [] }));
    const repo = { sample: { extractors: { filename: ['sample-([0-9.]+)[.]js'] }, vulnerabilities: vulnerabilities.concat(vulnerabilities) } };
    const scanner = require('./lib/scanner');
    let findings = 0;
    scanner.on('vulnerable-dependency-found', finding => {
      findings++;
      assert.deepEqual(finding.results[0].vulnerabilities.map(v => v.identifiers), identifiers);
    });
    scanner.scanJsFile('sample-1.0.js', repo, {}).then(() => assert.equal(findings, 1))
      .catch(error => { console.error(error); process.exitCode = 1; });
  `);
});

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

it('awaits OSV results before resolving file scans', () => {
  run(`
    const assert = require('node:assert/strict');
    const deps = require('./lib/depsdev');
    deps.checkOSV = async () => { await new Promise(r => setTimeout(r, 30)); return [{ below: '2', severity: 'high', cwe: [], identifiers: {}, info: [] }]; };
    const scanner = require('./lib/scanner');
    const repo = { sample: { extractors: { filename: ['sample-([0-9.]+)[.]js'] }, vulnerabilities: [] } };
    let emitted = false;
    scanner.on('vulnerable-dependency-found', () => emitted = true);
    (async () => {
      const pending = scanner.scanJsFile('sample-1.0.js', repo, { includeOsv: true });
      assert.ok(pending instanceof Promise);
      assert.equal(emitted, false);
      await pending;
      assert.equal(emitted, true);
      assert.ok(scanner.scanBowerFile('ignored', {}, { ignore: { paths: [/ignored/] } }) instanceof Promise);
    })().catch(e => { console.error(e); process.exitCode = 1; });
  `);
});

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
