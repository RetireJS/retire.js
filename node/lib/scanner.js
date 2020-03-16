
var retire = require('./retire'),
    fs     = require('fs'),
    crypto = require('crypto'),
    path   = require('path'),
    utils  = require('./utils'),
    emitter   = new require('events').EventEmitter;

var events = new emitter();

var hash = {
  'sha1' : function(data) {
    shasum   = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  }
};

function emitResults(finding, options) {
  removeIgnored(finding.results, options.ignore);
  if (retire.isVulnerable(finding.results)) {
    events.emit('vulnerable-dependency-found', finding);
  } else {
    events.emit('dependency-found', finding);
  }

}

function shouldIgnorePath(fileSpecs, ignores) {
  return utils.detect(ignores.paths, function(i) {
    return utils.detect(fileSpecs, function(j) {
      return i.test(j) || i.test(path.resolve(j)); 
    });
  });
}

function removeIgnored(results, ignores) {
  if (!ignores.hasOwnProperty('descriptors')) return;
  results.forEach(function(r) {
    if (!r.hasOwnProperty('vulnerabilities')) return;
    ignores.descriptors.forEach(function(i) {
      if (r.component !== i.component) return;
      if (i.version && r.version !== i.version) return;
      if (i.severity && r.severity !== i.severity) return;
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
  emitResults({file: file, results: results}, options);
}


function scanDependencies(dependencies, nodeRepo, options) {
  for (var i in dependencies) {
    var dependency = dependencies[i];
    var fileSpecs = [toModulePath(dependency)];
    if (dependency.component) {
      fileSpecs.push(dependency.component);
    }

    if (options.ignore && shouldIgnorePath(fileSpecs, options.ignore)) {
      continue;
    }
    results = retire.scanNodeDependency(dependencies[i].module, nodeRepo, options);
    emitResults({file: dependencies[i].file, results: results}, options);
  }
}

function toModulePath(dep) {
  function f(d) {
    if (d.parent) return f(d.parent) + '/node_modules/' + d.component;
    return '';
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
      emitResults({file: file, results: results}, options);
    }
  } catch (e) {
    options.log.warn('Could not parse file: ' + file);
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


