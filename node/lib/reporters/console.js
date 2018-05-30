var retire = require('../retire');
var utils = require('../utils');


function printResults(logger, finding, config) {
  if (finding.results && finding.results.length > 0) {
    var logFunc = retire.isVulnerable(finding.results) ? logger.warn : logger.info;
    var printed = {};
    finding.results.forEach(function(elm) {
      var key = elm.component + ' ' + elm.version;
      if (printed[key]) return;
      if (retire.isVulnerable([elm])) {
        logFunc(key + ' has known vulnerabilities:' + printVulnerability(logger, elm, config));
        if (elm.parent) {
          printParent(logFunc, elm, config);
        }
      }
      printed[key] = true;
    });
  }
}

function printParent(logFunc, comp, options) {
  if ('parent' in comp) printParent(logFunc, comp.parent, options);
  logFunc(new Array(comp.level).join(' ') + (comp.parent ? String.fromCharCode(8627) + ' ' : '') + comp.component + ' ' + comp.version);
}

function printVulnerability(logger, component, config) {
  var string = '';
  component.vulnerabilities.forEach(function(vulnerability){
    string += config.outputformat === 'clean' ? '\n   ' : ' ';
    if (vulnerability.severity) {
      string += 'severity: ' + vulnerability.severity + '; ';
    }
    if (vulnerability.identifiers) {
      string += utils.map(vulnerability.identifiers, function(id, name) {
        return name + ': ' + utils.flatten([id]).join(' ');
      }).join(', ') + '; ';
    }
    string += vulnerability.info.join(config.outputformat === 'clean' ? '\n' : ' ');
  });
  return string;
}

exports.configure = function(logger, writer, config, hash) {
    logger.logDependency = function(finding) { if (config.verbose) printResults(logger, finding, config); };
    logger.logVulnerableDependency = function(component) { printResults(logger, component, config); };
};