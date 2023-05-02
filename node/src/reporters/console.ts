import * as retire from '../retire';
import * as utils from '../utils';
import { Logger, LoggerOptions, type ConfigurableLogger } from '../reporting';
import { Component, Finding, Vulnerability } from '../types';

function printResults(logger: Logger, finding: Finding, config: LoggerOptions) {
  if (finding.results && finding.results.length > 0) {
    const logFunc = retire.isVulnerable(finding.results) ? logger.warn : logger.info;
    const printed = new Set<string>();
    finding.results.forEach((elm) => {
      if (!config.verbose && !retire.isVulnerable([elm])) return;
      const key = `${elm.component} ${elm.version}`;
      logFunc(finding.file);
      logFunc(` ${String.fromCharCode(8627)} ${key}`);
      if (printed.has(key)) return;
      if (retire.isVulnerable([elm])) {
        logFunc(`${key} has known vulnerabilities:${printVulnerability(elm, config)}`);
      }
      printed.add(key);
    });
  }
}

function printVulnerability(component: Component, config: LoggerOptions) {
  let string = '';
  component.vulnerabilities?.forEach((vulnerability: Vulnerability) => {
    string += config.outputformat === 'clean' ? '\n   ' : ' ';
    if (vulnerability.severity) {
      string += `severity: ${vulnerability.severity}; `;
    }
    if (vulnerability.identifiers) {
      string +=
        Object.entries(vulnerability.identifiers)
          .map(([name, id]) => {
            return `${name}: ${utils.flatten<string>([Array.isArray(id) ? id : [id]]).join(' ')}`;
          })
          .join(', ') + '; ';
    }
    string += vulnerability.info.join(config.outputformat === 'clean' ? '\n' : ' ');
  });
  return string;
}

export default {
  configure: (logger, _, config) => {
    logger.logDependency = (finding) => {
      if (config.verbose) printResults(logger, finding, config);
    };
    logger.logVulnerableDependency = (component) => {
      printResults(logger, component, config);
    };
  },
} as ConfigurableLogger;
