var retire = require('./retire'),
    _      = require('underscore'),
    fs     = require('fs'),
    crypto = require('crypto'),
    emitter   = new require('events').EventEmitter;

var events = new emitter();
var infoLog = console.log;
var warnLog = console.warn;

var hash = {
  'sha1' : function(data) {
    shasum   = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  }
};

function printResults(file, results, config) {
  if (!retire.isVulnerable(results) && !config.verbose) return;
  var log = infoLog;
  if (retire.isVulnerable(results)) {
    log = warnLog;
    events.emit('vulnerable-dependency-found');
  }
  if (results.length > 0) {
    log(file);
    results.forEach(function(elm) {
      var vuln = '';
      if (retire.isVulnerable([elm])) {
        vuln = ' has known vulnerabilities: ' + elm.vulnerabilities.join(' ');
      }
      log(' ' + String.fromCharCode(8627) + ' ' + elm.component + ' ' + elm.version + vuln);
    });
  }
}
function shouldIgnore(file, ignores) {
  return _.detect(ignores, function(i) { return file.indexOf(i) === 0; });
}


function scanJsFile(file, repo, config) {
  if (config.ignore && shouldIgnore(file, config.ignore)) {
    return;
  }
  var results = retire.scanFileName(file, repo);
  if (!retire.isVulnerable(results)) {
    results = retire.scanFileContent(fs.readFileSync(file), repo, hash);
  }  
  printResults(file, results, config);
}

function printParent(comp) {
  if ('parent' in comp) printParent(comp.parent);
  infoLog(new Array(comp.level).join(' ') + (comp.parent ? String.fromCharCode(8627) + ' ' : '') + comp.component + ' ' + comp.version);
}

function scanDependencies(dependencies, nodeRepo) {
    for (var i in dependencies) {
		results = retire.scanNodeDependency(dependencies[i], nodeRepo);
		if (retire.isVulnerable(results)) {
			events.emit('vulnerable-dependency-found');
			var result = results[0]; //Only single scan here
			warnLog(result.component + ' ' + result.version + ' has known vulnerabilities: ' + result.vulnerabilities.join(' '));
			if (result.parent) {
				printParent(result);
			}
		}
    }
}


exports.scanDependencies = function(dependencies, nodeRepo) {
	return scanDependencies(dependencies, nodeRepo);
};
exports.scanJsFile = function(file, repo, config) {
	return scanJsFile(file, repo, config);
};
exports.registerWarnLogger = function(logger) {
	warnLog = logger;
};
exports.registerInfoLogger = function(logger) {
	infoLog = logger;
};
exports.on = function(name, listener) {
	events.on(name, listener);
};


