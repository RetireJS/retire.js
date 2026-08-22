/*jshint esversion: 6 */

import { ConfigurableLogger, Hasher, Logger, LoggerOptions, Writer } from '../reporting';

import * as retire from '../retire';
import * as fs from 'fs';
import { Finding } from '../types';
import { generatePURL, vulnerabilityRepositories } from './utils';
import * as crypto from 'crypto';

function configureCycloneDXLogger(logger: Logger, writer: Writer, config: LoggerOptions, hash: Hasher) {
  let vulnsFound = false;
  const finalResults = {
    version: retire.version,
    start: new Date(),
    data: [] as Finding[],
    messages: [] as unknown[],
    errors: [] as unknown[],
  };
  logger.info = finalResults.messages.push;
  logger.debug = config.verbose
    ? finalResults.messages.push
    : () => {
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
    const propertyList = vulnerabilityRepositories(config.jsRepo).map((repo) => ({
      name: 'retirejs:vulnerability-repository',
      value: repo,
    }));
    if (config.insecure) {
      propertyList.push({ name: 'retirejs:ignore-repository-certificate-errors', value: 'true' });
    }
    const properties = propertyList
      .map(
        (property) => `
      <property name="${escapeXml(property.name)}">${escapeXml(property.value)}</property>`,
      )
      .join('');
    const seen = new Set<string>();
    const components = finalResults.data
      .filter((d) => d.results.length > 0)
      .map((r) =>
        r.results
          .map((dep) => {
            dep.version = (dep.version.split('.').length >= 3 ? dep.version : dep.version + '.0').replace(/-/g, '.');
            const filepath = r.file;
            let hashes = '';
            if (filepath) {
              const file = fs.readFileSync(filepath);
              hashes = `
          <hashes>
            <hash alg="MD5">${hash.md5(file)}</hash>
            <hash alg="SHA-1">${hash.sha1(file)}</hash>
            <hash alg="SHA-256">${hash.sha256(file)}</hash>
            <hash alg="SHA-512">${hash.sha512(file)}</hash>
          </hashes>`;
            }
            const purl = generatePURL(dep);
            if (seen.has(purl)) return '';
            seen.add(purl);
            const nameParts = dep.component.split('/').reverse();
            return `
    <component type="library">
      <name>${nameParts[0]}</name>${nameParts.length > 1 ? `\n      <group>${nameParts[1]}</group>` : ''}
      <version>${dep.version}</version>${hashes}
      <licenses>${mapLicenses(dep.licenses)}</licenses>
      <purl>${purl}</purl>
      <modified>false</modified>
    </component>`;
          })
          .join(''),
      )
      .join('');
    write(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:${crypto.randomUUID()}" version="1">
  <metadata>
    <timestamp>${finalResults.start.toISOString()}</timestamp>
    <tools>
        <tool>
            <vendor>RetireJS</vendor>
            <name>retire.js</name>
            <version>${retire.version}</version>
        </tool>
    </tools>${properties ? `
    <properties>${properties}
    </properties>` : ''}
  </metadata>
  <components>${components}
  </components>
</bom>`);
    writer.close(callback);
  };
}

function escapeXml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function mapLicenses(licenses: string[] | undefined) {
  if (!licenses) return '';
  if (licenses.length == 0) return '';
  if (licenses[0] == 'commercial') return '<license><name>Commercial</name></license>';
  return `<expression>${licenses[0]}</expression>`;
}

export default {
  configure: configureCycloneDXLogger,
} as ConfigurableLogger;
