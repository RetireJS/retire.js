
function info(options) {
	return function(message) {
		(options.logger || console.log)(message);
	};
}

function warn(options) {
	return function(message) {
		(options.warnlogger || options.logger || console.warn)(message);
	};
}

exports.pick = function(p, keys) {
	var result = {};
	keys.forEach(function(k) { 
		if (p.hasOwnProperty(k)) {
			result[k] = p[k];
		}
	});
	return result;
};

exports.extend = function(o, a) {
	var result = exports.pick(o, Object.keys(o));
	exports.map(a, function(v,k){ result[k] = v; });
	return result;
};

exports.map = function(o, fn) {
	return Object.keys(o).map(function(k) { return fn(o[k], k); });
};

exports.find = function(ar, fn) {
	for(var i in ar) { 
		if (fn(ar[i])) return ar[i];
	}
	return undefined;
};

exports.detect = exports.find;

exports.flatten = function(e) {
	return e.reduce(function(x,y) { return x.concat(y); }, []);
};

exports.log = function(options) {
	return { 
		info : info(options),
		warn : warn(options),
		verbose : options.verbose ? info(options) : function() {}
	};
};
exports.forwardEvent = function(emitter, event) {
	return function() {
		emitter.emit([event].concat(arguments));
	};
};

exports.every = function(things, predicate){
	return Object.keys(things)
		.map(function(k) { return predicate(k, things[k]); })
		.reduce(function(x,y) { return x && y; }, true);
};
