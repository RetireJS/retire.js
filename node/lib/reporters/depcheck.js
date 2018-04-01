/*jshint esversion: 6 */

var retire = require('../retire');
var fs = require('fs');


function configureDepCheckLogger(logger, writer, config, hash) {
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
		if (config.verbose && finding.results.length > 0) { 
			finalResults.data.push(finding); 
		} 
	};

	logger.close = function(callback) {
		var write = vulnsFound ? writer.err : writer.out;
		finalResults.start = finalResults.start.toISOString().replace("Z", "+0000");
		write(`<?xml version="1.0"?>
<analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.1.3.xsd">
  <scanInfo>
    <engineVersion>${retire.version}</engineVersion>
    <dataSource><name>${config.jsRepo || "Retire.js github js repo"}</name><timestamp>${finalResults.start}</timestamp></dataSource>
    <dataSource><name>${config.nodeRepo || "Retire.js github node repo"}</name><timestamp>${finalResults.start}</timestamp></dataSource>
   </scanInfo>
   <projectInfo>
   	<name>${config.path}</name>
    <reportDate>${finalResults.start}</reportDate>
    <credits>retire.js</credits>
   </projectInfo>
   <dependencies>`);
		write(finalResults.data.filter(d => d.results).map(r => r.results.map(dep => {
			var filepath = r.file || dep.file;
			var filename = filepath.split("/").slice(-1);
			var file = fs.readFileSync(filepath);
			var md5 = hash.md5(file);
			var sha1 = hash.sha1(file);
			var evidence = `
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
			var identifiers = `
        <identifier type="npm" confidence="HIGH">
           <name>(${dep.component}:${dep.version})</name>
        </identifier>`;
			var vulns = dep.vulnerabilities && dep.vulnerabilities.length > 0 ? dep.vulnerabilities.map(v => {
				var references = v.info.map(i => `
            <reference>
              <source>Retire.js</source>
              <url>${i}</url>
              <name>${i}</name>
            </reference>`).join("");
				var id = [v.identifiers && v.identifiers.CVE && v.identifiers.CVE[0], v.identifiers && v.identifiers.issue, dep.component + '@' + v.info[0]]	
					.filter(n => n !== null)[0];
				//TODO: Fix CVSS stuff - add to repo? add id to every bug in repo?
				return `
        <vulnerability source="retire">
          <name>${id}</name>
          <cvssScore>7.5</cvssScore>
          <cvssAccessVector>NETWORK</cvssAccessVector>
          <cvssAccessComplexity>LOW</cvssAccessComplexity>
          <cvssAuthenticationr>NONE</cvssAuthenticationr>
          <cvssConfidentialImpact>PARTIAL</cvssConfidentialImpact>
          <cvssIntegrityImpact>PARTIAL</cvssIntegrityImpact>
          <cvssAvailabilityImpact>PARTIAL</cvssAvailabilityImpact>
          <severity>${v.severity || "Medium"}</severity>
          <description>${v.identifiers && v.identifiers.summary || "None"}</description>
          <references>${references}
          </references>
          <vulnerableSoftware>
              <software>${ v.atOrAbove ? "&gt;= " + v.atOrAbove: "" } &lt; ${v.below}</software>
          </vulnerableSoftware>
        </vulnerability>`; 
      }).join('') : "";
      return `    <dependency>
      <fileName>${filename}</fileName>
      <filePath>${filepath}</filePath>
      <md5>${md5}</md5>
      <sha1>${sha1}</sha1>
      <evidenceCollected>${evidence}
      </evidenceCollected>
      <identifiers>${identifiers}
      </identifiers>
      <vulnerabilities>${vulns}
      </vulnerabilities>
    </dependency>`; }).join("\n")).join("\n"));
    write(`  </dependencies>
</analysis>`);
		writer.close(callback); 
	};
}


exports.configure = configureDepCheckLogger;
