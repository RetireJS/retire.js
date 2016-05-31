var retire = require('./retire'),
    fs     = require('fs'),
    crypto = require('crypto'),
    path   = require('path'),
    _      = require('underscore'),
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
    events.emit('vulnerable-dependency-found', {file: file, results: results});
  } else {
    events.emit('dependency-found', results);
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
      string += _.map(vulnerability.identifiers, function(id, name) {
        return name + ': ' + _.flatten([id]).join(' ');
      }).join(', ') + '; ';
    }
    string += vulnerability.info.join(options.outputformat === 'clean' ? '\n' : ' ');
  });
  return string;
}

function shouldIgnore(fileSpecs, ignores) {
  return _.detect(ignores, function(i) {
    return _.detect(fileSpecs, function(j) {
      return j.indexOf(i) === 0 || j.indexOf(path.resolve(i)) === 0 ; 
    });
  });
}


function scanJsFile(file, repo, options) {
  if (options.ignore && shouldIgnore([file], options.ignore)) {
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
    if (options.ignore && shouldIgnore([dependencies[i].component, toModulePath(dependencies[i])], options.ignore)) {
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


