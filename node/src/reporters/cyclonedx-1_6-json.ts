import { ConfigurableLogger, Hasher, Logger, LoggerOptions, Writer } from '../reporting';

import * as retire from '../retire';
import * as fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { Finding } from '../types';
import { generatePURL } from './utils';
import * as path from 'path';

function configureCycloneDXJSONLogger(logger: Logger, writer: Writer, config: LoggerOptions, hash: Hasher) {
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

  type Component = {
    evidence: {
      occurrences: Array<{ location: string }>;
    };
  };

  logger.close = function (callback) {
    const write = vulnsFound ? writer.err : writer.out;
    const seen = new Map<string, Component>();
    const components = finalResults.data
      .filter((d) => d.results)
      .map((r) =>
        r.results
          .map((dep) => {
            dep.version = (dep.version.split('.').length >= 3 ? dep.version : dep.version + '.0').replace(/-/g, '.');
            let hashes;
            const filepath = r.file;
            const evidence = { occurrences: [] as Array<{ location: string }> };
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
            const nameParts = dep.component.split('/').reverse();
            const result = {
              type: 'library',
              name: nameParts[0],
              group: nameParts[1],
              version: dep.version,
              purl: purl,
              hashes: hashes,
              evidence,
              licenses: mapLicenses(dep.licenses),
            };
            seen.set(purl, result);
            return result;
          })
          .filter((x) => x != undefined),
      )
      .reduce((a, b) => a.concat(b), []);
    write(
      JSON.stringify(
        {
          bomFormat: 'CycloneDX',
          specVersion: '1.6',
          serialNumber: `urn:uuid:${uuidv4()}`,
          version: 1,
          metadata: {
            timestamp: finalResults.start,
            tools: [
              {
                vendor: 'RetireJS',
                name: 'retire.js',
                version: retire.version,
              },
            ],
          },
          components: components,
        },
        undefined,
        2,
      ),
    );
    writer.close(callback);
  };
}

function mapLicenses(licenses: string[] | undefined) {
  if (!licenses) return [];
  if (licenses.length == 0) return [];
  if (licenses[0] == 'commercial') return [{ license: { name: 'Commercial' } }];
  return [{ expression: licenses[0] }];
}

export default {
  configure: configureCycloneDXJSONLogger,
} as ConfigurableLogger;
