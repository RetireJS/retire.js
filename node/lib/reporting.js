var retire = require('./retire');
var utils = require('./utils');
var fs = require('fs');
var crypto = require('crypto');

var verbose = false;
var outputformat = "normal";
var scanStart = Date.now();

var colorwarn = function(x) { return x; };


function hashContent(hash, content) {
	var h = crypto.createHash(hash);
	h.update(content);
	return h.digest('hex');	
}

md5Hash = (file) => hashContent('md5', file);
sha1Hash = (file) => hashContent('sha1', file);
sha256Hash = (file) => hashContent('sha256', file);
sha512Hash = (file) => hashContent('sha512', file);

var writer = {
	out: console.log,
	err: function(x) { console.warn(colorwarn(x)); },
	close : function(callback) { 
		process.stderr.on('drain', function() {
			process.stderr.on('drain', function() {
				callback();
			});
		});
	}
};

var logger = {
	info : function(x) { writer.out(x); },
	debug : function(x) { if (verbose) writer.out(x); },
	warn : function(x) { writer.err(x); },
	error : function(x) { writer.err(x); },

	logDependency : function(finding) { if (verbose) printResults(finding); },
	logVulnerableDependency: printResults,
	close: function(callback) { writer.close(callback); }
};



function printResults(finding) {
  if (finding.results && finding.results.length > 0) {
  	var logFunc = retire.isVulnerable(finding.results) ? logger.warn : logger.info;
    var printed = {};
    finding.results.forEach(function(elm) {
      var key = elm.component + ' ' + elm.version;
    	if (finding.file) {
    		logFunc(finding.file);
	      logFunc(' ' + String.fromCharCode(8627) + ' ' + key);
	  	} else {
	  		printParent(elm, logFunc);
	  	}
      if (printed[key]) return;
      if (retire.isVulnerable([elm])) {
        logFunc(key + ' has known vulnerabilities:' + printVulnerability(elm));
      }
      printed[key] = true;
    });
  }
}

function printVulnerability(component) {
  var string = '';
  component.vulnerabilities.forEach(function(vulnerability){
    string += outputformat === 'clean' ? '\n   ' : ' ';
    if (vulnerability.severity) {
      string += 'severity: ' + vulnerability.severity + '; ';
    }
    if (vulnerability.identifiers) {
      string += utils.map(vulnerability.identifiers, function(id, name) {
        return name + ': ' + utils.flatten([id]).join(' ');
      }).join(', ') + '; ';
    }
    string += vulnerability.info.join(outputformat === 'clean' ? '\n' : ' ');
  });
  return string;
}

function printParent(comp, logFunc) {
  if ('parent' in comp) printParent(comp.parent, logFunc);
  logFunc(new Array(comp.level).join(' ') + (comp.parent ? String.fromCharCode(8627) + ' ' : '') + comp.component + ' ' + comp.version);
}

function configureJsonLogger(config) {
	var vulnsFound = false;
	var finalResults = { version: retire.version, start: new Date(scanStart), data: [], messages: [], errors: [] };
	logger.info = finalResults.messages.push;
	logger.debug = config.verbose ? finalResults.messages.push : function() {};
	logger.warn = logger.error = finalResults.errors.push;
	logger.logVulnerableDependency = function(finding) {
		vulnsFound = true;
		finalResults.data.push(finding);
	};
	logger.logDependency = function(finding) { 
		if (verbose) { 
			finalResults.data.push(finding); 
		} 
	};
	logger.close = function(callback) {
		finalResults.time = (Date.now() - scanStart)/1000
		var write = vulnsFound ? writer.err : writer.out;
		write(JSON.stringify(finalResults));
		writer.close(callback); 
	};
}

function configureDepCheckLogger(config) {
	var vulnsFound = false;
	var finalResults = { version: retire.version, start: new Date(scanStart), data: [], messages: [], errors: [] };
	logger.info = finalResults.messages.push;
	logger.debug = config.verbose ? finalResults.messages.push : function() {};
	logger.warn = logger.error = finalResults.errors.push;
	logger.logVulnerableDependency = function(finding) {
		vulnsFound = true;
		finalResults.data.push(finding);
	};
	logger.logDependency = function(finding) { 
		if (verbose) { 
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
			var md5 = md5Hash(file);
			var sha1 = sha1Hash(file);
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
				let references = v.info.map(i => `
            <reference>
              <source>Retire.js</source>
              <url>${i}</url>
              <name>${i}</name>
            </reference>`).join("");
//				console.log(v.identifiers, [v.identifiers && v.identifiers.CVE, v.identifiers && v.identifiers.issue, dep.component + '@' + v.info[0]]);
				var id = [v.identifiers && v.identifiers.CVE && v.identifiers.CVE[0], v.identifiers && v.identifiers.issue, dep.component + '@' + v.info[0]]	
					.filter(n => n != null)[0];
				console.log(v);
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
        </vulnerability>`}).join('') : "";

			return `    <dependency>
      <fileName>${filename}</fileName>
      <filePath>${dep.file}</filePath>
      <md5>${md5}</md5>
      <sha1>${sha1}</sha1>
      <evidenceCollected>${evidence}
      </evidenceCollected>
      <identifiers>${identifiers}
      </identifiers>
      <vulnerabilities>${vulns}
      </vulnerabilities>
    </dependency>`}).join("\n")).join("\n"));
		write(`  </dependencies>
</analysis>`)
		writer.close(callback); 
	};
}

function configureCycloneDXLogger(config) {
	var vulnsFound = false;
	var finalResults = { version: retire.version, start: new Date(scanStart), data: [], messages: [], errors: [] };
	logger.info = finalResults.messages.push;
	logger.debug = config.verbose ? finalResults.messages.push : function() {};
	logger.warn = logger.error = finalResults.errors.push;
	logger.logVulnerableDependency = function(finding) {
		vulnsFound = true;
		finalResults.data.push(finding);
	};
	logger.logDependency = function(finding) { 
		if (verbose) { 
			finalResults.data.push(finding); 
		} 
	};

	logger.close = function(callback) {
		var write = vulnsFound ? writer.err : writer.out;
		finalResults.start = finalResults.start.toISOString().replace("Z", "+0000");
		var components = finalResults.data.filter(d => d.results).map(r => r.results.map(dep => {
			//TODO: Temporary fix untill dep-track relaxes version requirements
			dep.version = dep.version.split(".").length >= 3 ? dep.version : dep.version + ".0";
			var filepath = r.file || dep.file;
			var filename = filepath.split("/").slice(-1);
			var file = fs.readFileSync(filepath);
			return `
    <component type="framework">
      <name>${dep.component}</name>
      <version>${dep.version}</version>
      <hashes>
        <hash alg="MD5">${md5Hash(file)}</hash>
        <hash alg="SHA-1">${sha1Hash(file)}</hash>
        <hash alg="SHA-256">${sha256Hash(file)}</hash>
        <hash alg="SHA-512">${sha512Hash(file)}</hash>
      </hashes>
      <licenses><license></license></licenses>
      <purl>pkg:npm/${dep.component}@${dep.version}</purl>
      <modified>false</modified>
    </component>`
    }).join("")).join("");
		write(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.0" version="1">
  <components>${components}
  </components>
</bom>`)
		writer.close(callback); 
	};
}





function configureFileWriter(config) {
  var fileOutput = {
    fileDescriptor: fs.openSync(config.outputpath, "w")
  };
  if (fileOutput.fileDescriptor < 0) {
    console.error("Could not open " + config.outputpath + " for writing");
    process.exit(9);
  } 
  fileOutput.stream = fs.createWriteStream('', {fd: fileOutput.fileDescriptor});
  var writeToFile = function(message) {
    fileOutput.stream.write(message);
    fileOutput.stream.write('\n');
  };
  writer.out = writer.err = writeToFile;
  writer.close = function(callback) {
	  fileOutput.stream.on('finish', function() {
	    fs.close(fileOutput.fileDescriptor);
	    callback();
	  });
		fileOutput.stream.end();
  };
}





exports.open = function(config) {
	verbose = config.verbose;
	if (!config.nocolors) colorwarn = config.colorwarn;
	outputformat = config.outputformat;
  if (config.outputformat === 'json') {
  	configureJsonLogger(config);
  }
  if (config.outputformat === 'depcheck') {
  	configureDepCheckLogger(config);
  }
  if (config.outputformat === 'cyclonedx') {
  	configureCycloneDXLogger(config);
  }
	if (typeof config.outputpath === 'string') { 
		configureFileWriter(config); 
	}
	return logger;
};
