import { EventEmitter as Emitter} from "events";
import * as retire from "./retire";
import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";
import { ComponentDescriptor, Finding, Hasher, Options, Repository } from "./types";
import { Component } from "./types";

type Ignores = Required<Options>["ignore"];

const events = new Emitter();

const hash: Hasher = {
  'sha1' : function(data) {
    const shasum = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  }
};

function emitResults(finding: Finding, options: Options) {
  if (options.ignore) removeIgnored(finding.results, options.ignore);
  if (!options.verbose) finding.results = finding.results.filter(f => retire.isVulnerable([f]));
  if (finding.results.length == 0) return;
  if (retire.isVulnerable(finding.results)) {
    events.emit('vulnerable-dependency-found', finding);
  } else {
    events.emit('dependency-found', finding);
  }

}

function shouldIgnorePath(fileSpecs: string[], ignores: Ignores): boolean {
  return ignores.paths?.some((i) => {
    return fileSpecs.some((j) => i.test(j) || i.test(path.resolve(j)));
  }) ?? false;
}

function removeIgnored(results: Component[], ignores: Ignores) {
  if (!("descriptors" in ignores)) return;
  results.forEach((r) => {
    if (!("vulnerabilities" in r)) return;
    ignores.descriptors?.filter((d): d is ComponentDescriptor => "component" in d).forEach(function(i) {
      if (r.component !== i.component) return;
      if (i.version && r.version !== i.version) return;
      if (i.severity) { //Remove vulnerabilities with the severity we want to drop
        r.vulnerabilities = r.vulnerabilities?.filter(v => v.severity != i.severity);        
        return;
      }
      if (i.identifiers) {
        removeIgnoredVulnerabilitiesByIdentifier({...i.identifiers}, r);
        return;
      }
      r.vulnerabilities = [];
    });
    if (r.vulnerabilities?.length === 0) delete r.vulnerabilities;
  });
}

function removeIgnoredVulnerabilitiesByIdentifier(identifiers: Record<string, string | string[]> , result: Component) {
  result.vulnerabilities = result.vulnerabilities?.filter((v) => {
    if (!("identifiers" in v)) return true;
    return !Object.entries(identifiers || {}).every(([key, value]) => hasIdentifier({...v.identifiers}, key, value));
  });
}
function hasIdentifier(identifiers: Record<string, string | string[]>, key: string, value: string | string[]) {
  if (!(key in identifiers)) return false;
  const identifier = identifiers[key];
  return Array.isArray(identifier) ? identifier.some(function(x) { return x === value; }) : identifier === value;
}


export function scanJsFile(file: string, repo: Repository, options: Options) {
  if (options.ignore && shouldIgnorePath([file], options.ignore)) {
    return;
  }
  let results = retire.scanFileName(file, repo);
  if (!results || results.length === 0) {
    results = retire.scanFileContent(fs.readFileSync(file, "utf-8"), repo, hash);
  }
  emitResults({file: file, results: results}, options);
}

export function scanBowerFile(file: string, repo: Repository, options: Options) {
  if (options.ignore && shouldIgnorePath([file], options.ignore)) {
    return;
  }
  try {
    const bower = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (bower.version) {
      const results = retire.check(bower.name, bower.version, repo);
      emitResults({file: file, results: results}, options);
    }
  } catch (e) {
    options.log.warn('Could not parse file: ' + file);
  }
}

export function on(...args: Parameters<Emitter["on"]>) {
  events.on(...args);
};
