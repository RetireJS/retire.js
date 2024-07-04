/*jshint esversion: 8 */

var jsonLogger = require('../../lib/reporters/cyclonedx-json').default;
var jsonLogger1_6 = require('../../lib/reporters/cyclonedx-1_6-json').default;
var xmlLogger = require('../../lib/reporters/cyclonedx').default;
var fs = require('fs');
var Validator = require('jsonschema').Validator;
var retire = require('../../lib/retire');

var reporting = require('../../lib/reporting');
var hash = reporting.hash;
var repo = require('../repository.json');
var xsdValidator = require('xsd-schema-validator');

let jsonSchema = require('../schema/bom-1.4.schema.json');
let jsonSchema1_6 = require('../schema/bom-1.6.schema.json');

let jsfSchema = require('../schema/jsf-0.82.schema.json');

var path = require('path');
const { fail } = require('assert');
var os = require('os');
var tmpDir = os.tmpdir();
var jqFile = tmpDir + '/jquery.js';
fs.writeFileSync(jqFile, '/*! jQuery v1.8.1 asdasd ');
const relative = path.relative(process.cwd(), jqFile);

describe('cyclonedx-json', () => {
  it('should validate report according to schema', () => {
    let data = [];
    let writer = {
      out: (a) => data.push(a),
      err: (a) => data.push(a),
      close: () => undefined,
    };
    let logger = reporting.open({});
    jsonLogger.configure(logger, writer, {}, hash);
    let result1 = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hash);
    logger.logVulnerableDependency({ results: result1, file: jqFile });
    logger.close();
    let validator = new Validator();
    validator.addSchema(jsfSchema, 'jsf-0.82.schema.json#/definitions/signature');
    let output = JSON.parse(data.join(''));
    data.join('').should.contain('pkg:npm/jquery@1.8.1');
    let res = validator.validate(output, jsonSchema);
    res.valid.should.equal(true);
    output.bomFormat.should.equal('CycloneDX');
    output.specVersion.should.equal('1.4');
  });

  it('should validate report according to schema 1.6', () => {
    let data = [];
    let writer = {
      out: (a) => data.push(a),
      err: (a) => data.push(a),
      close: () => undefined,
    };
    let logger = reporting.open({});
    jsonLogger1_6.configure(logger, writer, {}, hash);
    let result1 = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hash);
    logger.logVulnerableDependency({ results: result1, file: jqFile });
    logger.close();
    let validator = new Validator();
    validator.addSchema(jsfSchema, 'jsf-0.82.schema.json#/definitions/signature');
    let output = JSON.parse(data.join(''));
    data.join('').should.contain('pkg:npm/jquery@1.8.1');
    let res = validator.validate(output, jsonSchema1_6);
    res.valid.should.equal(true);
    output.bomFormat.should.equal('CycloneDX');
    output.specVersion.should.equal('1.6');
    output.components[0].evidence.occurrences[0].location.should.equal(relative);
  });

  it('should validate report according to xml schema', async () => {
    let data = [];
    let writer = {
      out: (a) => data.push(a),
      err: (a) => data.push(a),
      close: () => undefined,
    };
    let logger = reporting.open({});
    xmlLogger.configure(logger, writer, {}, hash);
    let result = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hash);
    logger.logVulnerableDependency(result);
    logger.close();
    let xml = data.join('');
    try {
      let xsdResult = await xsdValidator.validateXML(xml, 'spec/schema/bom-1.4.xsd');
      if (!xsdResult.valid) {
        fail('XML not seen as valid', xsdResult);
      }
    } catch (e) {
      fail(e);
    }
  });
});
