/*jshint esversion: 6 */

import { ConfigurableLogger, Logger, Writer, Hasher, LoggerOptions } from '../reporting';

import * as retire from '../retire';
import * as fs from 'fs';
import { Finding } from '../types';

function configureDepCheckLogger(logger: Logger, writer: Writer, config: LoggerOptions, hash: Hasher) {
  let vulnsFound = false;
  const finalResults = {
    version: retire.version,
    start: new Date().toISOString().replace('Z', '+0000'),
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
  logger.logVulnerableDependency = (finding) => {
    vulnsFound = true;
    finalResults.data.push(finding);
  };
  logger.logDependency = (finding) => {
    if (config.verbose && finding.results.length > 0) {
      finalResults.data.push(finding);
    }
  };

  logger.close = (callback) => {
    const write = vulnsFound ? writer.err : writer.out;
    write(`<?xml version="1.0"?>
<analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.2.3.xsd">
  <scanInfo>
    <engineVersion>${retire.version}</engineVersion>
    <dataSource><name>${config.jsRepo || 'Retire.js github js repo'}</name><timestamp>${
      finalResults.start
    }</timestamp></dataSource>
   </scanInfo>
   <projectInfo>
   	<name>${config.path}</name>
    <reportDate>${finalResults.start}</reportDate>
    <credits>retire.js</credits>
   </projectInfo>
   <dependencies>`);
    write(
      finalResults.data
        .filter((d) => d.results)
        .map((r) =>
          r.results
            .map((dep, i) => {
              const filepath = r.file;
              if (!filepath) return;
              const filename = filepath.split('/').slice(-1);
              const file = fs.readFileSync(filepath);
              const md5 = hash.md5(file);
              const sha1 = hash.sha1(file);
              const sha256 = hash.sha256(file);
              const evidence = `
        <evidence type="product" confidence="HIGH">
          <source>file</source>
          <name>name</name>
          <value>${dep.component}</value>
        </evidence>
        <evidence type="version" confidence="HIGH">
          <source>file</source>
          <name>version</name>
          <value>${dep.version}</value>
        </evidence>`;
              const identifiers = `
        <package confidence="HIGH">
          <description>(${dep.component}:${dep.version})</description>
          <id>${i}</id>
        </package>`;
              const vulns =
                dep.vulnerabilities && dep.vulnerabilities.length > 0
                  ? dep.vulnerabilities
                      .map((v) => {
                        const references = v.info
                          .map(
                            (i) => `
            <reference>
              <source>Retire.js</source>
              <url>${i}</url>
              <name>${i}</name>
            </reference>`,
                          )
                          .join('');
                        //  const id = [v.identifiers && v.identifiers.CVE && v.identifiers.CVE[0], v.identifiers && v.identifiers.issue, dep.component + '@' + v.info[0]]
                        //  .filter(n => n !== null)[0];
                        //TODO: Fix CVSS stuff - add to repo? add id to every bug in repo?
                        return `
        <vulnerability source="retire">
          <name>${dep.component}:${dep.version}</name>
          <cvssV2>
            <score>7.5</score>
            <accessVector>NETWORK</accessVector>
            <accessComplexity>LOW</accessComplexity>
            <authenticationr>NONE</authenticationr>
            <confidentialImpact>PARTIAL</confidentialImpact>
            <integrityImpact>PARTIAL</integrityImpact>
            <availabilityImpact>PARTIAL</availabilityImpact>
            <severity>${v.severity || 'medium'}</severity>
          </cvssV2>
          <description>${(v.identifiers && v.identifiers.summary) || 'None'}</description>
          <references>${references}
          </references>
          <vulnerableSoftware>
              <software>${v.atOrAbove ? '&gt;= ' + v.atOrAbove : ''} &lt; ${v.below}</software>
          </vulnerableSoftware>
        </vulnerability>`;
                      })
                      .join('')
                  : '';
              return `    <dependency>
      <fileName>${filename}</fileName>
      <filePath>${filepath}</filePath>
      <md5>${md5}</md5>
      <sha1>${sha1}</sha1>
      <sha256>${sha256}</sha256>
      <evidenceCollected>${evidence}
      </evidenceCollected>
      <identifiers>${identifiers}
      </identifiers>
      <vulnerabilities>${vulns}
      </vulnerabilities>
    </dependency>`;
            })
            .join('\n'),
        )
        .join('\n'),
    );
    write(`  </dependencies>
</analysis>`);
    writer.close(callback);
  };
}

export default {
  configure: configureDepCheckLogger,
} as ConfigurableLogger;
