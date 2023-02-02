/*jshint esversion: 6 */

var retire = require('../retire');
var fs = require('fs');
var uuidv4 = require('uuid').v4;


function configureCycloneDXLogger(logger, writer, config, hash) {
    var vulnsFound = false;
    var finalResults = { version: retire.version, start: new Date(), data: [], messages: [], errors: [] };
    logger.info = finalResults.messages.push;
    logger.debug = config.verbose ? finalResults.messages.push : function() {};
    logger.warn = logger.error = finalResults.errors.push;
    logger.logVulnerableDependency = function(finding) {
        vulnsFound = true;
        finalResults.data.push(finding);
    };
    logger.logDependency = function(finding) {
        if (finding.results.length > 0) {
          finalResults.data.push(finding);
        }
    };

    logger.close = function(callback) {
      var write = vulnsFound ? writer.err : writer.out;
      var seen = {};
      var components = finalResults.data.filter(d => d.results).map(r => r.results.map(dep => {
          dep.version = (dep.version.split(".").length >= 3 ? dep.version : dep.version + ".0").replace(/-/g, ".");
          var filepath = r.file || dep.file;
          if (filepath) {
            var filename = filepath.split("/").slice(-1);
            var file = fs.readFileSync(filepath);
              hashes = `
          <hashes>
            <hash alg="MD5">${hash.md5(file)}</hash>
            <hash alg="SHA-1">${hash.sha1(file)}</hash>
            <hash alg="SHA-256">${hash.sha256(file)}</hash>
            <hash alg="SHA-512">${hash.sha512(file)}</hash>
          </hashes>`;
          }
          var purl = `pkg:npm/${dep.component}@${dep.version}`;
          var hashes = "";
          if (seen[purl]) return '';
          seen[purl] = true;
          return `
    <component type="library">
      <name>${dep.component}</name>
      <version>${dep.version}</version>${hashes}
      <purl>${purl}</purl>
      <modified>false</modified>
    </component>`;
    }).join("")).join("");
        write(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:${ uuidv4() }" version="1">
  <metadata>
    <timestamp>${finalResults.start.toISOString()}</timestamp>
    <tools>
        <tool>
            <vendor>RetireJS</vendor>
            <name>retire.js</name>
            <version>${ retire.version }</version>
        </tool>
    </tools>
  </metadata>
  <components>${components}
  </components>
</bom>`);
        writer.close(callback);
    };
}

exports.configure = configureCycloneDXLogger;