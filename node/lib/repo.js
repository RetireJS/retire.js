/* global require, console, exports */
var http   = require('https'),
    fs     = require('fs'),
	retire = require('./retire');
var emitter = require('events').EventEmitter;



function loadJson(url) {
	var events = new emitter();
	console.log('Downloading ' + url + ' ...');
	http.get(url, function (res) {
		var data = '';

		res.on('data', function (chunk){
			data += chunk;
		});

		res.on('end',function(){
			var obj = JSON.parse(retire.replaceVersion(data));
			events.emit('done', obj);
		});
	});
	return events;
}
function loadJsonFromFile(file) {
    console.log('Reading ' + file + ' ...');
	var events = new emitter();
    fs.readFile(file, {}, function(err, data) {
      var obj = JSON.parse(retire.replaceVersion(''+data));
      events.emit('done', obj);
    });
    return events;
}


exports.loadrepository = function(repoUrl) {
	return loadJson(repoUrl);
};
exports.loadrepositoryFromFile = function(filepath) {
	return loadJsonFromFile(filepath);
};