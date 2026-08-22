import { ConfigurableLogger, Hasher, Logger, LoggerOptions, Writer } from '../reporting';

import * as retire from '../retire';
import * as fs from 'fs';
import { Component as RetireComponent, Finding, Vulnerability } from '../types';
import { generatePURL, vulnerabilityRepositories } from './utils';
import * as path from 'path';
import * as crypto from 'crypto';

/**
 * Spec versions sharing this implementation. The 1.4 reporters are kept separate, as the
 * modern object form of metadata.tools was only introduced in 1.5.
 */
export type CycloneDXSpecVersion = '1.6' | '1.7';

const TOOL_BOM_REF = 'retirejs-tool';
const SCAN_TARGET_BOM_REF = 'retirejs:scan-target';

/**
 * Retire.js has no native confidence score, so the mapping from the detection method to a
 * CycloneDX identity technique and confidence is a heuristic. Both technique and confidence
 * are required by the schema.
 */
const identityTechniques: Record<string, { technique: string; confidence: number }> = {
  hash: { technique: 'hash-comparison', confidence: 1 },
  ast: { technique: 'ast-fingerprint', confidence: 0.9 },
  filecontent: { technique: 'source-code-analysis', confidence: 0.8 },
  filecontentreplace: { technique: 'source-code-analysis', confidence: 0.8 },
  func: { technique: 'dynamic-analysis', confidence: 0.8 },
  filename: { technique: 'filename', confidence: 0.5 },
  uri: { technique: 'filename', confidence: 0.5 },
};

type License = { expression: string } | { license: { name: string } };
type Occurrence = { location: string };
type IdentityMethod = { technique: string; confidence: number; value?: string };
type Identity = { field: 'version'; confidence: number; concludedValue: string; methods: IdentityMethod[] };
type Evidence = { occurrences: Occurrence[]; identity?: Identity[] };

type Component = {
  'bom-ref': string;
  type: 'library';
  name: string;
  group?: string;
  version: string;
  purl: string;
  hashes?: Array<{ alg: string; content: string }>;
  evidence: Evidence;
  licenses: License[];
};

type VulnerabilitySource = { name: string; url?: string };
type CycloneVulnerability = {
  id: string;
  source: VulnerabilitySource;
  cwes?: number[];
  description?: string;
  detail?: string;
  advisories: Array<{ url: string; title?: string }>;
  references: Array<{ id: string; source: { name: string; url: string } }>;
  ratings: Array<{
    source: VulnerabilitySource;
    severity: string;
  }>;
  affects: Array<{
    ref: string;
    versions: Array<{ range: string; status: 'affected' }>;
  }>;
};

function configureCycloneDXJSONLogger(
  specVersion: CycloneDXSpecVersion,
  logger: Logger,
  writer: Writer,
  config: LoggerOptions,
  hash: Hasher,
) {
  let vulnsFound = false;
  const finalResults = {
    version: retire.version,
    start: new Date().toISOString(),
    data: [] as Finding[],
    messages: [] as unknown[],
    errors: [] as unknown[],
  };
  logger.info = finalResults.messages.push;
  logger.debug = config.verbose
    ? finalResults.messages.push
    : function () {
        return;
      };
  logger.warn = logger.error = finalResults.errors.push;
  logger.logVulnerableDependency = function (finding) {
    vulnsFound = true;
    finalResults.data.push(finding);
  };
  logger.logDependency = function (finding) {
    if (finding.results.length > 0) {
      finalResults.data.push(finding);
    }
  };

  logger.close = function (callback) {
    const write = vulnsFound ? writer.err : writer.out;
    const seen = new Map<string, Component>();
    const vulnerabilitiesCyclone = new Map<string, CycloneVulnerability>();
    const includeVEX = config.outputformat?.endsWith('_VEX') ?? false;
    const vulnerabilityRepositoriesList = vulnerabilityRepositories(config.jsRepo);
    // Only attributable to a single URL when exactly one repository was used
    const retireSource: VulnerabilitySource = {
      name: 'Retire.js',
      url: vulnerabilityRepositoriesList.length === 1 ? vulnerabilityRepositoriesList[0] : undefined,
    };
    const properties = vulnerabilityRepositoriesList.map((repo) => ({
      name: 'retirejs:vulnerability-repository',
      value: repo,
    }));
    if (config.insecure) {
      properties.push({ name: 'retirejs:ignore-repository-certificate-errors', value: 'true' });
    }

    const components = finalResults.data
      .filter((d) => d.results)
      .map((r) =>
        r.results
          .map((dep) => {
            dep.version = (dep.version.split('.').length >= 3 ? dep.version : dep.version + '.0').replace(/-/g, '.');
            let hashes;
            const filepath = r.file;
            const evidence: Evidence = { occurrences: [] };
            if (filepath) {
              const file = fs.readFileSync(filepath);
              const relativePath = path.relative(process.cwd(), filepath);
              evidence.occurrences.push({ location: relativePath });
              hashes = [
                { alg: 'MD5', content: hash.md5(file) },
                { alg: 'SHA-1', content: hash.sha1(file) },
                { alg: 'SHA-256', content: hash.sha256(file) },
                { alg: 'SHA-512', content: hash.sha512(file) },
              ];
            }
            const purl = generatePURL(dep);
            const existing = seen.get(purl);
            if (existing) {
              const missing = evidence.occurrences.filter(
                (x) => !existing.evidence.occurrences.some((y) => y.location == x.location),
              );
              existing.evidence.occurrences.push(...missing);
              return undefined;
            }
            const identity = mapIdentity(dep);
            if (identity) evidence.identity = [identity];
            const nameParts = dep.component.split('/').reverse();
            const bomRef = purl;
            dep.vulnerabilities?.forEach((vuln) => {
              // Pick valid identifiers for VEX
              const ids: string[] | undefined =
                vuln.identifiers?.CVE ?? (vuln.identifiers?.githubID ? [vuln.identifiers.githubID] : undefined);
              if (!ids) return;
              ids.forEach((id) => {
                if (!vulnerabilitiesCyclone.has(id)) {
                  const { references, advisories } = mapUrls(vuln);
                  const cwes = vuln.cwe?.map((c) => parseInt(c.split('-')[1]));
                  vulnerabilitiesCyclone.set(id, {
                    id,
                    source: retireSource,
                    cwes: cwes?.length ? cwes : undefined,
                    description: vuln.identifiers?.summary,
                    detail: vuln.details,
                    advisories: advisories,
                    references: references,
                    ratings: [
                      {
                        source: retireSource,
                        severity: vuln.severity,
                      },
                    ],
                    affects: [],
                  });
                }
                vulnerabilitiesCyclone.get(id)!.affects.push({
                  ref: bomRef,
                  versions: [
                    {
                      // "vers:npm/1.2.3|>=2.0.0|<5.0.0"
                      range: 'vers:npm/' + (vuln.atOrAbove ? '>=' + vuln.atOrAbove + '|' : '') + '<' + vuln.below,
                      status: 'affected',
                    },
                  ],
                });
              });
            });
            const result: Component = {
              'bom-ref': bomRef,
              type: 'library',
              name: nameParts[0],
              group: nameParts[1],
              version: dep.version,
              purl: purl,
              hashes: hashes,
              evidence,
              licenses: mapLicenses(dep.licenses, specVersion),
            };
            seen.set(purl, result);
            return result;
          })
          .filter((x) => x != undefined),
      )
      .reduce((a, b) => a.concat(b), []);

    const dependencies = [
      { ref: SCAN_TARGET_BOM_REF, dependsOn: components.map((c) => c['bom-ref']) },
      ...components.map((c) => ({ ref: c['bom-ref'], dependsOn: [] as string[] })),
    ];

    write(
      JSON.stringify(
        {
          $schema: `http://cyclonedx.org/schema/bom-${specVersion}.schema.json`,
          bomFormat: 'CycloneDX',
          specVersion,
          serialNumber: `urn:uuid:${crypto.randomUUID()}`,
          version: 1,
          metadata: {
            timestamp: finalResults.start,
            tools: {
              components: [
                {
                  type: 'application',
                  'bom-ref': TOOL_BOM_REF,
                  group: 'RetireJS',
                  name: 'retire',
                  version: retire.version,
                },
              ],
            },
            component: {
              type: 'application',
              'bom-ref': SCAN_TARGET_BOM_REF,
              name: scanTargetName(config.path),
            },
            properties: properties.length ? properties : undefined,
          },
          components: components,
          dependencies,
          vulnerabilities: includeVEX ? Array.from(vulnerabilitiesCyclone.values()) : undefined,
        },
        undefined,
        2,
      ),
    );
    writer.close(callback);
  };
}

function scanTargetName(scanPath: string | undefined): string {
  return path.basename(path.resolve(scanPath ?? '.'));
}

function mapIdentity(component: RetireComponent): Identity | undefined {
  if (!component.detection) return undefined;
  const mapped = identityTechniques[component.detection];
  if (!mapped) return undefined;
  return {
    field: 'version',
    confidence: mapped.confidence,
    concludedValue: component.version,
    methods: [{ technique: mapped.technique, confidence: mapped.confidence, value: component.detection }],
  };
}

function mapLicense(license: string): License {
  return license == 'commercial' ? { license: { name: 'Commercial' } } : { expression: license };
}

function mapLicenses(licenses: string[] | undefined, specVersion: CycloneDXSpecVersion): License[] {
  if (!licenses) return [];
  if (licenses.length == 0) return [];
  // Before 1.7, the licenses array could hold at most one SPDX expression, and expressions
  // could not be mixed with named licenses.
  if (specVersion === '1.6') return [mapLicense(licenses[0])];
  return licenses.map(mapLicense);
}

function mapUrls(vulnerability: Vulnerability) {
  const references = [];
  if (vulnerability.identifiers?.CVE) {
    const nvdlink = `https://nvd.nist.gov/vuln/detail/${vulnerability.identifiers.CVE[0]}`;
    references.push({ id: vulnerability.identifiers.CVE[0], source: { name: 'NVD', url: nvdlink } });
  }
  if (vulnerability.identifiers?.githubID) {
    const ghsa = `https://github.com/advisories/${vulnerability.identifiers.githubID}`;
    references.push({ id: vulnerability.identifiers.githubID, source: { name: 'GitHub Advisories', url: ghsa } });
  }
  const advisories = vulnerability.info
    .filter(
      (url) => !url.startsWith('https://nvd.nist.gov/vuln/detail/') && !url.startsWith('https://github.com/advisories/'),
    )
    .map((u) => ({ url: u }));
  return { references, advisories };
}

export function cycloneDXJSONLogger(specVersion: CycloneDXSpecVersion): ConfigurableLogger {
  return {
    configure: (logger, writer, config, hash) => configureCycloneDXJSONLogger(specVersion, logger, writer, config, hash),
  };
}
