import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import jsonLogger from '../../lib/reporters/cyclonedx-json';
import jsonLogger1_6 from '../../lib/reporters/cyclonedx-1_6-json';
import * as fs from 'fs';
import { Schema, Validator } from 'jsonschema';
import * as retire from '../../lib/retire';
import { hash, LoggerOptions, Writer } from '../../lib/reporting';
import * as reporting from '../../lib/reporting';

function readJson<T>(path: string): T {
  const data = fs.readFileSync(path, 'utf8');
  return JSON.parse(data) as T;
}

const repo = readJson<Repository>('spec/repository.json');

const jsonSchema = readJson<Schema>('spec/schema/bom-1.4.schema.json');
const jsonSchema1_6 = readJson<Schema>('spec/schema/bom-1.6.schema.json');
const jsfSchema = readJson<Schema>('spec/schema/jsf-0.82.schema.json');

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
  jsRepo: 'testrepo.json',
};

describe('cyclonedx-json', () => {
  it('should validate report according to schema', () => {
    const data: unknown[] = [];
    const writer: Writer = {
      out: (a) => data.push(a),
      err: (a) => data.push(a),
      close: () => undefined,
    };
    const logger = reporting.open(loggerOptions);
    jsonLogger.configure(logger, writer, loggerOptions, hash);
    const result1 = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hash);
    result1[0].licenses = ['MIT'];
    logger.logVulnerableDependency({ results: result1, file: jqFile });
    logger.close();
    const validator = new Validator();
    validator.addSchema(jsfSchema, 'jsf-0.82.schema.json#/definitions/signature');
    const output = JSON.parse(data.join(''));
    assert.ok(data.join('').includes('pkg:npm/jquery@1.8.1'));
    const res = validator.validate(output, jsonSchema);
    assert.strictEqual(res.valid, true);
    assert.strictEqual(output.bomFormat, 'CycloneDX');
    assert.strictEqual(output.specVersion, '1.4');
  });

  it('should validate report according to schema 1.6', () => {
    const data: unknown[] = [];
    const writer: Writer = {
      out: (a) => data.push(a),
      err: (a) => data.push(a),
      close: () => undefined,
    };
    const logger = reporting.open(loggerOptions);
    jsonLogger1_6.configure(logger, writer, loggerOptions, hash);
    const result1 = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hash);
    result1[0].licenses = ['MIT'];
    logger.logVulnerableDependency({ results: result1, file: jqFile });
    logger.close();
    const validator = new Validator();
    validator.addSchema(jsfSchema, 'jsf-0.82.schema.json#/definitions/signature');
    const output = JSON.parse(data.join(''));
    assert.ok(data.join('').includes('pkg:npm/jquery@1.8.1'));
    const res = validator.validate(output, jsonSchema1_6);
    assert.strictEqual(res.valid, true);
    assert.strictEqual(output.bomFormat, 'CycloneDX');
    assert.strictEqual(output.specVersion, '1.6');
    assert.strictEqual(output.components[0].evidence.occurrences[0].location, relative);
  });

  /*it('should validate report according to xml schema', async () => {
    const data: unknown[] = [];
    const writer: Writer = {
      out: (a) => data.push(a),
      err: (a) => data.push(a),
      close: () => undefined,
    };
    const logger = reporting.open(loggerOptions);
    xmlLogger.configure(logger, writer, loggerOptions, hash);
    const result = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hash);
    result[0].licenses = ['MIT'];
    logger.logVulnerableDependency({ results: result, file: jqFile });
    logger.close();
    const xml = data.join('');
    assert.ok(xml.includes('pkg:npm/jquery@1.8.1'));
    try {
      const parsedXml = libxmljs.parseXml(xml);
      const bomschema = libxmljs.parseXml(fs.readFileSync('spec/schema/bom-1.4.xsd', 'utf8'));
      //const spdx = fs.readFileSync('spec/schema/spdx.xsd', 'utf8');
      bomschema.child(1)?.setAttribute('schemaLocation', path.resolve('spec/schema/spdx.xsd'));
      const x = parsedXml.validate(bomschema) as boolean;
      assert.strictEqual(x, true);
    } catch (e) {
      console.warn(e);
      fail('XML not seen as valid: ' + e);
    }
  });*/
});
