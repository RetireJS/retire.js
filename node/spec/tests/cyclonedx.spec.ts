import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import jsonLogger from '../../lib/reporters/cyclonedx-json';
import jsonLogger1_6 from '../../lib/reporters/cyclonedx-1_6-json';
import jsonLogger1_7 from '../../lib/reporters/cyclonedx-1_7-json';
import * as fs from 'fs';
import { Schema, Validator } from 'jsonschema';
import * as retire from '../../lib/retire';
import { ConfigurableLogger, hash, LoggerOptions, Writer } from '../../lib/reporting';
import * as reporting from '../../lib/reporting';

function readJson<T>(path: string): T {
  const data = fs.readFileSync(path, 'utf8');
  return JSON.parse(data) as T;
}

const repo = readJson<Repository>('spec/repository.json');

const jsonSchema = readJson<Schema>('spec/schema/bom-1.4.schema.json');
const jsonSchema1_6 = readJson<Schema>('spec/schema/bom-1.6.schema.json');
const jsonSchema1_7 = readJson<Schema>('spec/schema/bom-1.7.schema.json');
const jsfSchema = readJson<Schema>('spec/schema/jsf-0.82.schema.json');
const spdxSchema = readJson<Schema>('spec/schema/spdx.schema.json');

import * as path from 'path';

import * as os from 'os';
import { Repository } from '../../lib/types';

const tmpDir = os.tmpdir();
const jqFile = tmpDir + '/jquery.js';
fs.writeFileSync(jqFile, '/*! jQuery v1.8.1 asdasd ');
const relative = path.relative(process.cwd(), jqFile);

const loggerOptions: LoggerOptions = {
  outputformat: 'cyclonedx',
  outputpath: '',
  verbose: false,
  colors: false,
  path: '.',
  colorwarn: () => '',
  jsRepo: ['testrepo.json'],
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function runReporter(reporter: ConfigurableLogger, options: LoggerOptions, licenses: string[] = ['MIT']): any {
  const data: unknown[] = [];
  const writer: Writer = {
    out: (a) => data.push(a),
    err: (a) => data.push(a),
    close: () => undefined,
  };
  const logger = reporting.open(options);
  reporter.configure(logger, writer, options, hash);
  const results = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hash);
  results[0].licenses = licenses;
  logger.logVulnerableDependency({ results, file: jqFile });
  logger.close();
  return JSON.parse(data.join(''));
}

function validate(output: unknown, schema: Schema) {
  const validator = new Validator();
  validator.addSchema(jsfSchema, 'jsf-0.82.schema.json#/definitions/signature');
  validator.addSchema(spdxSchema, 'http://cyclonedx.org/schema/spdx.schema.json');
  return validator.validate(output, schema);
}

describe('cyclonedx-json', () => {
  it('should validate report according to schema', () => {
    const output = runReporter(jsonLogger, loggerOptions);
    const res = validate(output, jsonSchema);
    assert.strictEqual(res.valid, true, res.errors.join('\n'));
    assert.strictEqual(output.components[0].purl, 'pkg:npm/jquery@1.8.1');
    assert.strictEqual(output.bomFormat, 'CycloneDX');
    assert.strictEqual(output.specVersion, '1.4');
    assert.deepStrictEqual(output.metadata.properties, [
      { name: 'retirejs:vulnerability-repository', value: 'testrepo.json' },
    ]);
  });

  for (const { version, reporter, schema } of [
    { version: '1.6', reporter: jsonLogger1_6, schema: jsonSchema1_6 },
    { version: '1.7', reporter: jsonLogger1_7, schema: jsonSchema1_7 },
  ]) {
    const suffix = version.replace('.', '_');

    it(`should validate report according to schema ${version}`, () => {
      const options = { ...loggerOptions, outputformat: `cyclonedxJSON${suffix}` };
      const output = runReporter(reporter, options);
      const res = validate(output, schema);
      assert.strictEqual(res.valid, true, res.errors.join('\n'));
      assert.strictEqual(output.components[0].purl, 'pkg:npm/jquery@1.8.1');
      assert.strictEqual(output.bomFormat, 'CycloneDX');
      assert.strictEqual(output.specVersion, version);
      assert.strictEqual(output.$schema, `http://cyclonedx.org/schema/bom-${version}.schema.json`);
      assert.strictEqual(output.components[0].evidence.occurrences[0].location, relative);
      assert.deepStrictEqual(output.metadata.properties, [
        { name: 'retirejs:vulnerability-repository', value: 'testrepo.json' },
      ]);
      // Vulnerabilities are only included in the VEX variants
      assert.strictEqual(output.vulnerabilities, undefined);
    });

    it(`should use the modern metadata.tools form in ${version}`, () => {
      const options = { ...loggerOptions, outputformat: `cyclonedxJSON${suffix}` };
      const output = runReporter(reporter, options);
      assert.ok(!Array.isArray(output.metadata.tools), 'metadata.tools should not use the deprecated array form');
      assert.deepStrictEqual(output.metadata.tools.components, [
        {
          type: 'application',
          'bom-ref': 'retirejs-tool',
          group: 'RetireJS',
          name: 'retire',
          version: retire.version,
        },
      ]);
    });

    it(`should describe the scan target and dependency graph in ${version}`, () => {
      const options = { ...loggerOptions, outputformat: `cyclonedxJSON${suffix}` };
      const output = runReporter(reporter, options);
      const scanTarget = output.metadata.component;
      assert.strictEqual(scanTarget.type, 'application');
      assert.strictEqual(scanTarget['bom-ref'], 'retirejs:scan-target');
      assert.strictEqual(scanTarget.name, path.basename(process.cwd()));
      assert.deepStrictEqual(output.dependencies, [
        { ref: 'retirejs:scan-target', dependsOn: ['pkg:npm/jquery@1.8.1'] },
        { ref: 'pkg:npm/jquery@1.8.1', dependsOn: [] },
      ]);
    });

    it(`should report the detection technique as identity evidence in ${version}`, () => {
      const options = { ...loggerOptions, outputformat: `cyclonedxJSON${suffix}` };
      const output = runReporter(reporter, options);
      assert.deepStrictEqual(output.components[0].evidence.identity, [
        {
          field: 'version',
          confidence: 0.8,
          concludedValue: '1.8.1',
          methods: [{ technique: 'source-code-analysis', confidence: 0.8, value: 'filecontent' }],
        },
      ]);
    });

    it(`should validate VEX report according to schema ${version}`, () => {
      const options = { ...loggerOptions, outputformat: `cyclonedxJSON${suffix}_VEX` };
      const output = runReporter(reporter, options);
      const res = validate(output, schema);
      assert.strictEqual(res.valid, true, res.errors.join('\n'));
      assert.ok(output.vulnerabilities.length > 0);
      const vulnerability = output.vulnerabilities[0];
      assert.deepStrictEqual(vulnerability.source, { name: 'Retire.js', url: 'testrepo.json' });
      assert.deepStrictEqual(vulnerability.ratings[0].source, { name: 'Retire.js', url: 'testrepo.json' });
      assert.deepStrictEqual(vulnerability.cwes, [79]);
      assert.strictEqual(vulnerability.affects[0].ref, 'pkg:npm/jquery@1.8.1');
      assert.strictEqual(vulnerability.affects[0].versions[0].status, 'affected');
      assert.ok(vulnerability.affects[0].versions[0].range.startsWith('vers:npm/'));
    });
  }

  it('should emit only the first license as an expression in 1.6', () => {
    const options = { ...loggerOptions, outputformat: 'cyclonedxJSON1_6' };
    const output = runReporter(jsonLogger1_6, options, ['MIT', 'BSD-2-Clause']);
    // Multiple SPDX expressions are not representable before 1.7
    assert.deepStrictEqual(output.components[0].licenses, [{ expression: 'MIT' }]);
    assert.strictEqual(validate(output, jsonSchema1_6).valid, true);
  });

  it('should emit every license as a separate expression in 1.7', () => {
    const options = { ...loggerOptions, outputformat: 'cyclonedxJSON1_7' };
    const output = runReporter(jsonLogger1_7, options, ['MIT', 'BSD-2-Clause']);
    assert.deepStrictEqual(output.components[0].licenses, [{ expression: 'MIT' }, { expression: 'BSD-2-Clause' }]);
    const res = validate(output, jsonSchema1_7);
    assert.strictEqual(res.valid, true, res.errors.join('\n'));
  });

  it('should map a commercial license to a named license in 1.7', () => {
    const options = { ...loggerOptions, outputformat: 'cyclonedxJSON1_7' };
    const output = runReporter(jsonLogger1_7, options, ['commercial', 'MIT']);
    assert.deepStrictEqual(output.components[0].licenses, [
      { license: { name: 'Commercial' } },
      { expression: 'MIT' },
    ]);
    const res = validate(output, jsonSchema1_7);
    assert.strictEqual(res.valid, true, res.errors.join('\n'));
  });
});
