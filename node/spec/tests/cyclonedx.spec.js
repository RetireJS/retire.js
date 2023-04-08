/*jshint esversion: 8 */

var jsonLogger = require("../../lib/reporters/cyclonedx-json");
var xmlLogger = require("../../lib/reporters/cyclonedx");
var fs = require("fs");
var Validator = require('jsonschema').Validator;
var retire = require("../../lib/retire");

var reporting = require("../../lib/reporting");
var hash = reporting.hash;
var repo = require("../repository.json");
var libxmljs = require("libxmljs");

let jsonSchema = require("../schema/bom-1.4.schema.json");
let jsfSchema = require("../schema/jsf-0.82.schema.json");
const { fail } = require("assert");

describe('cyclonedx-json', () => {

    it("should validate report according to schema", () => {
        let data = [];
        let writer = {
            out: (a) => data.push(a),
            err: (a) => data.push(a),
            close: () => {}
        };
        let logger = reporting.open({});
        jsonLogger.configure(logger, writer, {}, hash);
        let result = retire.scanFileContent("/*! jQuery v1.8.1 asdasd ", repo, hash);
        logger.logVulnerableDependency({ results: result });
        logger.close();
        let validator = new Validator();
        validator.addSchema(jsfSchema, "jsf-0.82.schema.json#/definitions/signature");
        let output = JSON.parse(data.join(""));
        let res = validator.validate(output, jsonSchema);
        res.valid.should.equal(true);
    });

    it("should not produce invalid output for duplicates", () => {
        let data = [];
        let writer = {
            out: (a) => data.push(a),
            err: (a) => data.push(a),
            close: () => {}
        };
        let logger = reporting.open({});
        jsonLogger.configure(logger, writer, {}, hash);
        let result = retire.scanFileContent("/*! jQuery v1.8.1 asdasd ", repo, hash);
        let result2 = retire.scanFileContent("/*! jQuery v1.8.1 asdasd ", repo, hash);
        logger.logVulnerableDependency({ results: result });
        logger.logVulnerableDependency({ results: result2 });
        logger.close();
        let validator = new Validator();
        validator.addSchema(jsfSchema, "jsf-0.82.schema.json#/definitions/signature");
        let output = JSON.parse(data.join(""));
        let res = validator.validate(output, jsonSchema);
        res.valid.should.equal(true);
    });


    it("should validate report according to xml schema", () => {
        let data = [];
        let writer = {
            out: (a) => data.push(a),
            err: (a) => data.push(a),
            close: () => {}
        };
        let logger = reporting.open({});
        xmlLogger.configure(logger, writer, {}, hash);
            let result = retire.scanFileContent("/*! jQuery v1.8.1 asdasd ", repo, hash);
        logger.logVulnerableDependency(result);
        logger.close();
        let xml = data.join("");
        let xmlDoc = libxmljs.parseXml(xml);
        let schemaS = fs.readFileSync("spec/schema/bom-1.4.xsd", "utf-8");
        let schema = libxmljs.parseXml(schemaS, { baseUrl: "spec/schema/" });
        let res = xmlDoc.validate(schema);
        if (!res) {
            fail(xmlDoc.validationErrors);
        }
    });
});
