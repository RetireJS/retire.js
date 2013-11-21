/* global require, console, exports */
var fs      = require('fs'),
    req     = require('request'),
	retire  = require('./retire');
var emitter = require('events').EventEmitter;


function loadJson(url, options) {
	var events = new emitter();
    var request = req;
    var logger = options.log || console.log;
	logger('Downloading ' + url + ' ...');
	if (options.proxy) {
        request = request.defaults({'proxy' : options.proxy});
    }
    request.get(url, function (e, r, data) {
        var obj = JSON.parse(retire.replaceVersion(data));
        events.emit('done', obj);
    });
	return events;
}

function loadJsonFromFile(file) {
    var logger = options.log || console.log;
    logger('Reading ' + file + ' ...');
	var events = new emitter();
    fs.readFile(file, {}, function(err, data) {
      var obj = JSON.parse(retire.replaceVersion(''+data));
      events.emit('done', obj);
    });
    return events;
}


exports.loadrepository = function(repoUrl, options) {
	return loadJson(repoUrl, options);
};
exports.loadrepositoryFromFile = function(filepath) {
	return loadJsonFromFile(filepath);
};