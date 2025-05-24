import { EventEmitter as Emitter } from 'events';
import * as retire from './retire';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import { ComponentDescriptor, Finding, Hasher, Options, Repository, Vulnerability } from './types';
import { Component } from './types';
import { checkOSV } from './depsdev';
import { deepScan } from './deepscan';
import { evaluateLicense } from './license';

type Ignores = Required<Options>['ignore'];

const events = new Emitter();

const hash: Hasher = {
  sha1: (data) => {
    const shasum = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  },
};

function emitResults(finding: Finding, options: Options, repo: Repository) {
  if (options.includeOsv === true) {
    Promise.all(
      finding.results.map((r) =>
        checkOSV(r.component, r.version, options).then(
          (v) => (r.vulnerabilities = (r.vulnerabilities ?? []).concat(v)),
        ),
      ),
    ).then(() => filterAndEmitResults(finding, options, repo));
  } else {
    filterAndEmitResults(finding, options, repo);
  }
}

function getIdentifiers(v: Vulnerability) {
  return (v.identifiers?.CVE ?? [])
    .concat(v.identifiers?.bug ?? [])
    .concat(v.identifiers?.issue ?? [])
    .concat(v.identifiers?.githubID ?? []);
}

function uniqueVulnerabilities(vulnerabilities?: Vulnerability[]): Vulnerability[] | undefined {
  if (!vulnerabilities) return undefined;
  const unique: Vulnerability[] = [];
  for (const v of vulnerabilities) {
    if (!unique.some((u) => getIdentifiers(u).some((i) => getIdentifiers(v).includes(i)))) {
      unique.push(v);
    }
  }
  return unique;
}
function addLicenses(components: Component[], repo: Repository) {
  components.forEach((c) => {
    const possibleLicenses = repo[c.component]?.licenses;
    if (possibleLicenses) c.licenses = evaluateLicense(possibleLicenses, c.version);
  });
}

function filterAndEmitResults(finding: Finding, options: Options, repo: Repository) {
  finding.results.forEach((r) => (r.vulnerabilities = uniqueVulnerabilities(r.vulnerabilities)));
  if (options.ignore) removeIgnored(finding.results, options.ignore);
  if (finding.results.length == 0) return;
  addLicenses(finding.results, repo);
  if (retire.isVulnerable(finding.results)) {
    events.emit('vulnerable-dependency-found', finding);
  } else {
    events.emit('dependency-found', finding);
  }
}

function shouldIgnorePath(fileSpecs: string[], ignores: Ignores): boolean {
  return (
    ignores.paths?.some((i) => {
      return fileSpecs.some((j) => i.test(j) || i.test(path.resolve(j)));
    }) ?? false
  );
}

function removeIgnored(results: Component[], ignores: Ignores) {
  if (!('descriptors' in ignores)) return;
  results.forEach((r) => {
    if (!('vulnerabilities' in r)) return;
    ignores.descriptors
      ?.filter((d): d is ComponentDescriptor => 'component' in d)
      .forEach((i) => {
        if (r.component !== i.component) return;
        if (i.version && r.version !== i.version) return;
        if (i.severity) {
          //Remove vulnerabilities with the severity we want to drop
          r.vulnerabilities = r.vulnerabilities?.filter((v) => v.severity != i.severity);
          return;
        }
        if (i.identifiers) {
          removeIgnoredVulnerabilitiesByIdentifier({ ...i.identifiers }, r);
          return;
        }
        r.vulnerabilities = [];
      });
    if (r.vulnerabilities?.length === 0) delete r.vulnerabilities;
  });
}

function removeIgnoredVulnerabilitiesByIdentifier(identifiers: Record<string, string | string[]>, result: Component) {
  result.vulnerabilities = result.vulnerabilities?.filter((v) => {
    if (!('identifiers' in v)) return true;
    return !Object.entries(identifiers || {}).every(([key, value]) => hasIdentifier({ ...v.identifiers }, key, value));
  });
}
function hasIdentifier(identifiers: Record<string, string | string[]>, key: string, value: string | string[]) {
  if (!(key in identifiers)) return false;
  const identifier = identifiers[key];
  return Array.isArray(identifier) ? identifier.some((x) => x === value) : identifier === value;
}

export function scanJsFile(file: string, repo: Repository, options: Options) {
  if (options.ignore && shouldIgnorePath([file], options.ignore)) {
    return;
  }
  let results = retire.scanFileName(file, repo, true);
  if (!results || results.length === 0) {
    const content = fs.readFileSync(file, 'utf-8');
    results = retire.scanFileContent(content, repo, hash);
    if (options.deep) {
      try {
        results = results.concat(deepScan(content, repo));
      } catch(e) {
        options.log.warn(`Failed to scan ${file}: ` + e);
      }
    }
  }
  emitResults({ file: file, results: results }, options, repo);
}

export function scanBowerFile(file: string, repo: Repository, options: Options) {
  if (options.ignore && shouldIgnorePath([file], options.ignore)) {
    return;
  }
  try {
    const bower = JSON.parse(fs.readFileSync(file, 'utf-8'));
    if (bower.version) {
      const results = retire.check(bower.name, bower.version, repo);
      emitResults({ file: file, results: results }, options, repo);
    }
  } catch (e) {
    options.log.warn(`Could not parse file: ${file}`);
  }
}

export function on(event: 'vulnerable-dependency-found' | 'dependency-found', handler: (finding: Finding) => void) {
  events.on(event, handler);
}
