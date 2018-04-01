var retire = require('../retire');

function configureJsonLogger(logger, writer, config) {
	var scanStart = Date.now();
	var vulnsFound = false;
	var finalResults = { version: retire.version, start: new Date(), data: [], messages: [], errors: [] };
	logger.info = finalResults.messages.push;
	logger.debug = config.verbose ? finalResults.messages.push : function() {};
	logger.warn = logger.error = finalResults.errors.push;
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
		var write = vulnsFound ? writer.err : writer.out;
		write(JSON.stringify(finalResults));
		writer.close(callback); 
	};
}

exports.configure = configureJsonLogger;