var retire = require('./retire');
var utils = require('./utils');
var fs = require('fs');

var verbose = false;
var outputformat = "normal";
var scanStart = Date.now();

var colorwarn = function(x) { return x; }

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
	var finalResults = { version: retire.version, start: new Date(scanStart), time: (Date.now() - scanStart)/1000, data: [], messages: [], errors: [] };
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
		write(JSON.stringify(finalResults));
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
	if (typeof config.outputpath === 'string') { 
		configureFileWriter(config); 
	}
	return logger;
};
