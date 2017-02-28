
var retire = require('./retire'),
    fs     = require('fs'),
    crypto = require('crypto'),
    path   = require('path'),
    utils  = require('./utils'),
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
  removeIgnored(results, options.ignore);
  if (!retire.isVulnerable(results) && !options.verbose) return;
  var logger = log(options).info;
  if (retire.isVulnerable(results)) {
    logger = log(options).warn;
    events.emit('vulnerable-dependency-found', {file: file, results: results});
  } else {
    events.emit('dependency-found', {file: file, results: results});
  }
  if (results.length > 0) {
    logger(file);
    var printed = {};
    results.forEach(function(elm) {
      var vuln = '';
      var key = elm.component + ' ' + elm.version;
      if (printed[key]) return;
      if (retire.isVulnerable([elm])) {
        vuln = ' has known vulnerabilities:' + printVulnerability(elm, options);
      }
      logger(' ' + String.fromCharCode(8627) + ' ' + key + vuln);
      printed[key] = true;
    });
  }
}

function printVulnerability(component, options) {
  var string = '';
  component.vulnerabilities.forEach(function(vulnerability){
    string += options.outputformat === 'clean' ? '\n   ' : ' ';
    if (vulnerability.severity) {
      string += 'severity: ' + vulnerability.severity + '; ';
    }
    if (vulnerability.identifiers) {
      string += utils.map(vulnerability.identifiers, function(id, name) {
        return name + ': ' + utils.flatten([id]).join(' ');
      }).join(', ') + '; ';
    }
    string += vulnerability.info.join(options.outputformat === 'clean' ? '\n' : ' ');
  });
  return string;
}

function shouldIgnorePath(fileSpecs, ignores) {
  return utils.detect(ignores.paths, function(i) {
    return utils.detect(fileSpecs, function(j) {
      return j.indexOf(i) === 0 || j.indexOf(path.resolve(i)) === 0 ; 
    });
  });
}

function removeIgnored(results, ignores) {
  if (!ignores.hasOwnProperty("descriptors")) return;
  results.forEach(function(r) {
    if (!r.hasOwnProperty("vulnerabilities")) return;
    ignores.descriptors.forEach(function(i) {
      if (r.component !== i.component) return;
      if (i.version && r.version !== i.version) return;
      if (i.identifiers) {
        removeIgnoredVulnerabilitiesByIdentifier(i.identifiers, r);
        return;
      }
      r.vulnerabilities = [];
    });
    if (r.vulnerabilities.length === 0) delete r.vulnerabilities;
  });
}

function removeIgnoredVulnerabilitiesByIdentifier(identifiers, result) {
  result.vulnerabilities = result.vulnerabilities.filter(function(v) {
    if (!v.hasOwnProperty("identifiers")) return true;
    return !utils.every(identifiers, function(key, value) { return hasIdentifier(v, key, value); });
  });
}
function hasIdentifier(vulnerability, key, value) {
  if (!vulnerability.identifiers.hasOwnProperty(key)) return false;
  var identifier = vulnerability.identifiers[key];
  return Array.isArray(identifier) ? identifier.some(function(x) { return x === value; }) : identifier === value;
}


function scanJsFile(file, repo, options) {
  if (options.ignore && shouldIgnorePath([file], options.ignore)) {
    return;
  }
  var results = retire.scanFileName(file, repo);
  if (!results || results.length === 0) {
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
    if (options.ignore && shouldIgnorePath([dependencies[i].component, toModulePath(dependencies[i])], options.ignore)) {
      continue;
    }
    results = retire.scanNodeDependency(dependencies[i], nodeRepo);
    if (retire.isVulnerable(results)) {
      events.emit('vulnerable-dependency-found', {results: results});
      var result = results[0]; //Only single scan here
      log(options).warn(result.component + ' ' + result.version + ' has known vulnerabilities: ' + printVulnerability(result, options));
      if (result.parent) {
        printParent(result, options);
      }
    } else {
      events.emit('dependency-found', results);
    }
  }
}

function toModulePath(dep) {
  function f(d) {
    if (d.parent) return f(d.parent) + "/node_modules/" + d.component;
    return "";
  }
  return path.resolve(f(dep).substring(1));
}



function scanBowerFile(file, repo, options) {
  if (options.ignore && shouldIgnorePath([file], options.ignore)) {
    return;
  }
  try {
    var bower = JSON.parse(fs.readFileSync(file));
    if (bower.version) {
      var results = retire.check(bower.name, bower.version, repo);
      printResults(file, results, options);
    }
  } catch (e) {
    log(options).warn('Could not parse file: ' + file);
  }
}



exports.scanDependencies = function(dependencies, nodeRepo, options) {
	return scanDependencies(dependencies, nodeRepo, options);
};
exports.scanJsFile = function(file, repo, options) {
	return scanJsFile(file, repo, options);
};
exports.scanBowerFile = function(file, repo, options) {
  return scanBowerFile(file, repo, options);
};
exports.on = function(name, listener) {
	events.on(name, listener);
};


