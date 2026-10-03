import { it } from 'node:test';
import { run } from '../run-script';

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
