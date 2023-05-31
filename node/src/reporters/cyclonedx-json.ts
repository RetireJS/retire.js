/*jshint esversion: 6 */

import { ConfigurableLogger, Hasher, Logger, LoggerOptions, Writer } from '../reporting';

import * as retire from '../retire';
import * as fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { Finding } from '../types';
import { generatePURL } from './utils';

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

  logger.close = function (callback) {
    const write = vulnsFound ? writer.err : writer.out;
    const seen = new Set<string>();
    const components = finalResults.data
      .filter((d) => d.results)
      .map((r) =>
        r.results
          .map((dep) => {
            dep.version = (dep.version.split('.').length >= 3 ? dep.version : dep.version + '.0').replace(/-/g, '.');
            let hashes;
            const filepath = r.file;
            if (filepath) {
              const file = fs.readFileSync(filepath);
              hashes = [
                { alg: 'MD5', content: hash.md5(file) },
                { alg: 'SHA-1', content: hash.sha1(file) },
                { alg: 'SHA-256', content: hash.sha256(file) },
                { alg: 'SHA-512', content: hash.sha512(file) },
              ];
            }
            const purl = generatePURL(dep);
            if (seen.has(purl)) return undefined;
            seen.add(purl);
            return {
              type: 'library',
              name: dep.component,
              version: dep.version,
              purl: purl,
              hashes: hashes,
            };
          })
          .filter((x) => x != undefined),
      )
      .reduce((a, b) => a.concat(b), []);
    write(
      JSON.stringify(
        {
          bomFormat: 'CycloneDX',
          specVersion: '1.4',
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

export default {
  configure: configureCycloneDXJSONLogger,
} as ConfigurableLogger;
