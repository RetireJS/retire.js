/* global require, exports */

var npm     = require("npm"),
	findit  = require("findit"),
	emitter = require("events").EventEmitter;


function listdep(name, dep, sep, deps) {
	for (var i in dep.dependencies) {
		deps.push({ component: i, version: dep.dependencies[i].version });
		listdep(i, dep.dependencies[i], sep + " ", deps);
	}
}

function getNodeDependencies() {
	var events = new emitter();
	npm.load({}, function() {
		npm.commands.ls([], true, function (er, _, pkginfo) {
			var deps = [];
			listdep(pkginfo.name, pkginfo, "", deps);
			events.emit("done", pkginfo);
		});
	});
	return events;
}

function scanJsFiles(path) {
	var finder = findit.find(path);
	finder.on("file", function (file) {
		if (file.match(/\.js$/)) {
			finder.emit("js", file);
		}
	});
	return finder;
}

exports.scanJsFiles = function() {
	return scanJsFiles(".");
};

exports.getNodeDependencies = function() {
	return getNodeDependencies();
};

