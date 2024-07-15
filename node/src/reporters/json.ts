/*jshint esversion: 6 */

import { ConfigurableLogger } from '../reporting';

import * as retire from '../retire';

export default {
  configure: (logger, writer, config) => {
    const scanStart = Date.now();
    const finalResults = {
      version: retire.version,
      start: new Date(),
      data: [] as unknown[],
      messages: [] as unknown[],
      errors: [] as unknown[],
      time: undefined as undefined | number,
    };
    logger.info = finalResults.messages.push;
    logger.debug = config.verbose
      ? finalResults.messages.push
      : () => {
          return;
        };
    logger.warn = logger.error = (message) => finalResults.errors.push(message);
    logger.logVulnerableDependency = (finding) => {
      if (!config.verbose) {
        finding.results = finding.results.filter((r) => retire.isVulnerable([r]));
      }
      finalResults.data.push(finding);
    };
    logger.logDependency = function (finding) {
      if (config.verbose && finding.results.length > 0) {
        finalResults.data.push(finding);
      }
    };
    logger.close = function (callback) {
      finalResults.time = (Date.now() - scanStart) / 1000;
      const res = config.outputformat === 'jsonsimple' ? finalResults.data : finalResults;
      writer.out(JSON.stringify(res));
      writer.close(callback);
    };
  },
} as ConfigurableLogger;
