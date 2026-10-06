import { beforeEach, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { setTimeout } from 'node:timers/promises';
import * as depsdev from '../../lib/depsdev';
import * as retire from '../../lib/retire';
import * as scanner from '../../lib/scanner';
import { Finding, Repository, Vulnerability } from '../../lib/types';
import { options } from '../options';
import repository from '../../../repository/jsrepository-v6.json';

const findings: Finding[] = [];
scanner.on('vulnerable-dependency-found', (finding) => findings.push(finding));
beforeEach(() => {
  findings.length = 0;
});

it('preserves distinct Bootstrap CVEs sharing an issue while removing repeated advisories', async (t) => {
  const repo = JSON.parse(retire.replaceVersion(JSON.stringify(repository)));
  const vulnerabilities = retire.check('bootstrap', '4.0.0', repo)[0].vulnerabilities!;
  t.mock.method(depsdev, 'checkOSV', async () => vulnerabilities.concat(vulnerabilities));

  await scanner.scanJsFile('bootstrap-4.0.0.js', repo, { ...options, includeOsv: true });
  await scanner.scanJsFile('bootstrap-4.0.0.js', repo, { ...options, includeOsv: true });

  assert.equal(findings.length, 2);
  for (const finding of findings) {
    const actual = finding.results[0].vulnerabilities!;
    assert.equal(actual.length, 4);
    assert.deepEqual(actual.flatMap((v) => v.identifiers.CVE).sort(), [
      'CVE-2018-14040',
      'CVE-2018-14041',
      'CVE-2018-14042',
      'CVE-2019-8331',
    ]);
  }
});

it('keeps fallback identifier namespaces separate and prefers canonical identifiers', async () => {
  const identifiers = [
    { issue: '123' },
    { bug: '123' },
    { CVE: ['CVE-2026-1234'], issue: '123' },
    { githubID: 'GHSA-abcd-1234-abcd', bug: '123' },
  ];
  const vulnerabilities: Vulnerability[] = identifiers.map((identifiers) => ({
    below: '2',
    severity: 'high',
    cwe: [],
    identifiers,
    info: [],
  }));
  const repo: Repository = {
    sample: {
      extractors: { filename: ['sample-([0-9.]+)[.]js'] },
      vulnerabilities: vulnerabilities.concat(vulnerabilities),
    },
  };

  await scanner.scanJsFile('sample-1.0.js', repo, options);

  assert.equal(findings.length, 1);
  assert.deepEqual(
    findings[0].results[0].vulnerabilities!.map((v) => v.identifiers),
    identifiers,
  );
});

it('awaits OSV results before resolving JavaScript and Bower scans', async (t) => {
  t.mock.method(depsdev, 'checkOSV', async () => {
    await setTimeout(30);
    return [{ below: '2', severity: 'high', cwe: [], identifiers: {}, info: [] }];
  });
  const repo: Repository = {
    sample: { extractors: { filename: ['sample-([0-9.]+)[.]js'] }, vulnerabilities: [] },
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-bower-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'bower.json');
  fs.writeFileSync(file, JSON.stringify({ name: 'sample', version: '1.0' }));

  const pending = scanner.scanJsFile('sample-1.0.js', repo, { ...options, includeOsv: true });
  assert.equal(findings.length, 0);
  await pending;
  assert.equal(findings.length, 1);

  const bowerPending = scanner.scanBowerFile(file, repo, { ...options, includeOsv: true });
  assert.equal(findings.length, 1);
  await bowerPending;
  assert.equal(findings.length, 2);

  await scanner.scanBowerFile(file, repo, { ...options, ignore: { ...options.ignore, paths: [/bower\.json$/] } });
  assert.equal(findings.length, 2);
});

it('propagates Bower scan failures but warns on malformed Bower JSON', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-bower-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'bower.json');
  fs.writeFileSync(file, JSON.stringify({ name: 'sample', version: '1.0' }));
  const repo: Repository = { sample: { extractors: {}, vulnerabilities: [] } };
  const warnings: string[] = [];
  const config = {
    ...options,
    includeOsv: true,
    log: { ...options.log, warn: (message: string) => warnings.push(message) },
  };
  const error = new Error('Scan failed');
  t.mock.method(depsdev, 'checkOSV', async () => {
    throw error;
  });

  await assert.rejects(scanner.scanBowerFile(file, repo, config), error);
  assert.deepEqual(warnings, []);

  fs.writeFileSync(file, '{');
  await scanner.scanBowerFile(file, repo, config);
  assert.deepEqual(warnings, [`Could not parse file: ${file}`]);
});
