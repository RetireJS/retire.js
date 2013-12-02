var retire = require('./retire'),
    _      = require('underscore'),
    fs     = require('fs'),
    crypto = require('crypto'),
    log    = require('./utils').log,
    emitter   = new require('events').EventEmitter;

var events = new emitter();

var hash = {
  'sha1' : function(data) {
    shasum   = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  }
};

function printResults(file, results, options) {
  if (!retire.isVulnerable(results) && !options.verbose) return;
  var logger = log(options).info;
  if (retire.isVulnerable(results)) {
    logger = log(options).warn;
    events.emit('vulnerable-dependency-found');
  }
  if (results.length > 0) {
    logger(file);
    results.forEach(function(elm) {
      var vuln = '';
      if (retire.isVulnerable([elm])) {
        vuln = ' has known vulnerabilities: ' + elm.vulnerabilities.join(' ');
      }
      logger(' ' + String.fromCharCode(8627) + ' ' + elm.component + ' ' + elm.version + vuln);
    });
  }
}
function shouldIgnore(file, ignores) {
  return _.detect(ignores, function(i) { return file.indexOf(i) === 0; });
}


function scanJsFile(file, repo, options) {
  if (options.ignore && shouldIgnore(file, options.ignore)) {
    return;
  }
  var results = retire.scanFileName(file, repo);
  if (!retire.isVulnerable(results)) {
    results = retire.scanFileContent(fs.readFileSync(file), repo, hash);
  }  
  printResults(file, results, options);
}

function printParent(comp, options) {
  if ('parent' in comp) printParent(comp.parent, options);
  log(options).info(new Array(comp.level).join(' ') + (comp.parent ? String.fromCharCode(8627) + ' ' : '') + comp.component + ' ' + comp.version);
}

function scanDependencies(dependencies, nodeRepo, options) {
    for (var i in dependencies) {
		results = retire.scanNodeDependency(dependencies[i], nodeRepo);
		if (retire.isVulnerable(results)) {
			events.emit('vulnerable-dependency-found');
			var result = results[0]; //Only single scan here
			log(options).warn(result.component + ' ' + result.version + ' has known vulnerabilities: ' + result.vulnerabilities.join(' '));
			if (result.parent) {
				printParent(result, options);
			}
		}
    }
}


exports.scanDependencies = function(dependencies, nodeRepo, options) {
	return scanDependencies(dependencies, nodeRepo, options);
};
exports.scanJsFile = function(file, repo, options) {
	return scanJsFile(file, repo, options);
};
exports.on = function(name, listener) {
	events.on(name, listener);
};


