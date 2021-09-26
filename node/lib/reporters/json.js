/*jshint esversion: 6 */

var retire = require('../retire');

function configureJsonLogger(logger, writer, config) {
	var scanStart = Date.now();
	var vulnsFound = false;
	var finalResults = { version: retire.version, start: new Date(), data: [], messages: [], errors: [] };
	logger.info = finalResults.messages.push;
	logger.debug = config.verbose ? finalResults.messages.push : function() {};
	logger.warn = logger.error = (message) => finalResults.errors.push(message);
	logger.logVulnerableDependency = function(finding) {
		vulnsFound = true;
		finalResults.data.push(finding);
	};
	logger.logDependency = function(finding) { 
		if (config.verbose && finding.results.length > 0) { 
			finalResults.data.push(finding); 
		} 
	};
	logger.close = function(callback) {
		finalResults.time = (Date.now() - scanStart)/1000;
		var res = (config.outputformat === "jsonsimple") ? finalResults.data : finalResults;
		writer.out(JSON.stringify(res));
		writer.close(callback); 
	};
}

exports.configure = configureJsonLogger;
