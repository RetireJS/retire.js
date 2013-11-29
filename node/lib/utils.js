
function info(options) {
	return function(message) {
		(options.logger || console.log)(message);
	};
};

function warn(options) {
	return function(message) {
		(options.warnlogger || options.logger || console.warn)(message);
	};
};

exports.log = function(options) {
	return { 
		info : info(options),
		warn : warn(options),
		verbose : options.verbose ? info(options) : function() {}
	}
};
