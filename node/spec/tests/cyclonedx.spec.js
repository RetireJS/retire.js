/*jshint esversion: 8 */

var jsonLogger = require('../../lib/reporters/cyclonedx-json').default;
var xmlLogger = require('../../lib/reporters/cyclonedx').default;
var fs = require('fs');
var Validator = require('jsonschema').Validator;
var retire = require('../../lib/retire');

var reporting = require('../../lib/reporting');
var hash = reporting.hash;
var repo = require('../repository.json');
var xsdValidator = require('xsd-schema-validator');

let jsonSchema = require('../schema/bom-1.4.schema.json');
let jsfSchema = require('../schema/jsf-0.82.schema.json');
const { fail } = require('assert');

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
    logger.logVulnerableDependency({ results: result1 });
    logger.close();
    let validator = new Validator();
    validator.addSchema(jsfSchema, 'jsf-0.82.schema.json#/definitions/signature');
    let output = JSON.parse(data.join(''));
    data.join('').should.contain('pkg:npm/jquery@1.8.1');
    let res = validator.validate(output, jsonSchema);
    res.valid.should.equal(true);
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
