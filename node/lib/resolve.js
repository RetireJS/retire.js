/* global require, exports */

var npm     = require('npm'),
	walkdir = require('walkdir'),
	fs		= require('fs'),
	readInstalled = require("read-installed"),
	emitter = require('events').EventEmitter;


function listdep(parent, filter, dep, level, deps) {
	for (var i in dep.dependencies) {
		if (filter !== null && filter.indexOf(i) == -1) {
			continue;
		}
		var d = { component: i, version: dep.dependencies[i].version, parent: parent, level: level };
		deps.push(d);
		listdep(d, null, dep.dependencies[i], level + 1, deps);
	}
}

function getNodeDependencies(path, limit) {
	var events = new emitter();
	readInstalled(path, null, null, function (er, pkginfo) {
		var deps = [];
		var filter = null;
		if (limit) {
			var packages = JSON.parse(fs.readFileSync('package.json'));
			filter = [];
			for(var k in packages.dependencies) filter.push(k);
		}
		listdep({component: pkginfo.name, version: pkginfo.version}, filter, pkginfo, 1, deps);
		events.emit('done', deps);				
	});
	return events;
}

function scanJsFiles(path) {
	var finder = walkdir.find(path);
	finder.on('file', function (file) {
		if (file.match(/\.js$/)) {
			finder.emit('jsfile', file);
		}
	});
	return finder;
}

exports.scanJsFiles = function(path) {
	return scanJsFiles(path);
};

exports.getNodeDependencies = function(limit) {
	return getNodeDependencies(limit);
};

