/*jshint esversion: 6 */

var retire = require('../retire');
var fs = require('fs');


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
		finalResults.start = finalResults.start.toISOString().replace("Z", "+0000");
		var seen = {};
		var components = finalResults.data.filter(d => d.results).map(r => r.results.map(dep => {
			//TODO: Temporary fix untill dep-track relaxes version requirements
			dep.version = dep.version.split(".").length >= 3 ? dep.version : dep.version + ".0";
			var filepath = r.file || dep.file;
			var filename = filepath.split("/").slice(-1);
			var file = fs.readFileSync(filepath);
			var purl = `pkg:npm/${dep.component}@${dep.version}`;
			if (seen[purl]) return '';
			seen[purl] = true;
			return `
    <component type="library">
      <name>${dep.component}</name>
      <version>${dep.version}</version>
      <hashes>
        <hash alg="MD5">${hash.md5(file)}</hash>
        <hash alg="SHA-1">${hash.sha1(file)}</hash>
        <hash alg="SHA-256">${hash.sha256(file)}</hash>
        <hash alg="SHA-512">${hash.sha512(file)}</hash>
      </hashes>
      <licenses><license></license></licenses>
      <purl>${purl}</purl>
      <modified>false</modified>
    </component>`;
    }).join("")).join("");
		write(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.0" version="1">
  <components>${components}
  </components>
</bom>`);
		writer.close(callback); 
	};
}

exports.configure = configureCycloneDXLogger;