import https from 'https';
import { Component, Repository, Options } from './types';
import { check } from './retire';
import { SeverityLevel } from './types';
import { Vulnerability } from './types';

type VersionInfo = {
  advisoryKeys: Array<{ id: string }>;
  isDefault: boolean;
  versionKey: {
    system: string;
    name: string;
    version: string;
  };
  licenses: string[];
  links: Array<{ label: string; url: string }>;
};

type Advisory = {
  advisoryKey: { id: string };
  url: string;
  title: string;
  aliases: string[];
  cvss3Score: number;
  cvss3Vector: string;
};

type OsvAdvisory = {
  withdrawn?: string;
  aliases: string[];
  summary: string;
  severity: Array<{ score: string; type: 'UNSPECIFIED' | 'CVSS_V3' }>;
  references: Array<{ url: string }>;
  affected: Array<{
    ranges: Array<{
      events: Array<{
        introduced: string;
        fixed: string;
      }>;
    }>;
  }>;
  database_specific?: {
    cwe_ids?: string[];
  };
};

function loadJson<T>(url: string, options: Options): Promise<T | undefined> {
  options.log.debug('Downloading ' + url + ' ...');
  return new Promise((resolve, reject) => {
    const req = https.request(url, (res) => {
      if (res.statusCode == 404) return resolve(undefined);
      if (res.statusCode != 200) {
        return reject('HTTP ' + res.statusCode + ' ' + res.statusMessage + ' for ' + url);
      }
      const data: Buffer[] = [];
      res.on('data', (c) => data.push(c));
      res.on('end', () => {
        const result = Buffer.concat(data).toString();
        resolve(JSON.parse(result) as T);
      });
    });
    req.on('error', (err) => {
      reject(err);
    });
    req.end();
  });
}

function getVulnerabilities(packageName: string, version: string, options: Options): Promise<VersionInfo | undefined> {
  return loadJson(`https://api.deps.dev/v3alpha/systems/npm/packages/${packageName}/versions/${version}`, options);
}
function scoreToSeverity(score: number): SeverityLevel {
  if (score > 7) return 'high';
  if (score > 4) return 'medium';
  return 'low';
}

async function loadAdvisory(packageName: string, version: string, id: string, options: Options): Promise<Component[]> {
  const osvAdvisory = await loadJson<OsvAdvisory>(`https://api.osv.dev/v1/vulns/${id}`, options);
  const advisory = await loadJson<Advisory>(`https://api.deps.dev/v3alpha/advisories/${id}`, options);
  if (!advisory || !osvAdvisory) return [];
  const simplifiedRepo: Repository = {
    [packageName]: {
      vulnerabilities: osvAdvisory.affected
        .map(({ ranges }) =>
          ranges.map(({ events }) => ({
            atOrAbove: events[0].introduced,
            below: events[0].fixed,
            severity: scoreToSeverity(advisory.cvss3Score),
            cwe: osvAdvisory.database_specific?.cwe_ids ?? [],
            identifiers: {
              githubID: id,
              CVE: osvAdvisory.aliases.filter((x) => x.startsWith('CVE-')),
              summary: advisory.title,
            },
            info: osvAdvisory.references.map(({ url }) => url),
          })),
        )
        .reduce((a, b) => a.concat(b), []),
      extractors: {},
    },
  };
  return check(packageName, version, simplifiedRepo);
}

export async function checkOSV(packageName: string, version: string, options: Options): Promise<Vulnerability[]> {
  try {
    const versionInfo = await getVulnerabilities(packageName, version, options);
    if (!versionInfo) return [];
    if (versionInfo.advisoryKeys.length == 0) return [];
    const comps = await Promise.all(
      versionInfo.advisoryKeys.map(({ id }) => loadAdvisory(packageName, version, id, options)),
    );
    const flattened = comps.reduce((a, b) => a.concat(b), []);
    return flattened.map((x) => x.vulnerabilities ?? []).reduce((a, b) => a.concat(b), []);
  } catch (e) {
    options.log.warn('Error checking OSV: ' + e);
    return [];
  }
}
