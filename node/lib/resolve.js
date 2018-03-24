/* global require, exports */

var walkdir			= require('walkdir'),
	fs						= require('fs'),
	readInstalled	= require('read-installed'),
	emitter				= require('events').EventEmitter;


function listdep(parent, dep, level, deps) {
	var stack = [];
	stack.push({parent: parent, dep: dep, level: level}); 
	while (typeof (o = stack.pop()) !== 'undefined') {
		for (var i in o.dep.dependencies) {
			cyclic = false;
			dep_parent = o.parent;
			while (typeof dep_parent !== 'undefined') {
				if (dep_parent.component === i) {
					cyclic = true;
					break;
				} else {
					dep_parent = dep_parent.parent;
				}
			}
			if (cyclic) {
				continue;
			}
			var d = { file: 'node_modules/' + i + '/package.json',component: i, version: o.dep.dependencies[i].version, parent: o.parent, level: o.level };
			deps.push(d);
			stack.push({parent: d, dep: o.dep.dependencies[i], level: o.level + 1}); 
		}
	}
}

function getNodeDependencies(path, limit) {
	var events = new emitter();
	readInstalled(path, {}, function (er, pkginfo) {
		var deps = [];
		if (limit) {
			var packages = JSON.parse(fs.readFileSync(path +'/package.json'));
			filter = [];			

			var filter = packages.dependencies ? Object.keys(packages.dependencies) : [];
			Object.keys(pkginfo.dependencies)
				.filter(function(d) { return filter.indexOf(d) == -1; })
				.forEach(function(d) { delete pkginfo.dependencies[d]; });
		}
		listdep({file: 'package.json',component: pkginfo.name, version: pkginfo.version}, pkginfo, 1, deps);
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
		if (file.match(/\/bower.json$/)) {
			finder.emit('bowerfile', file);
		}
	});
	return finder;
}

exports.scanJsFiles = function(path) {
	return scanJsFiles(path);
};

exports.getNodeDependencies = function(path, limit) {
	return getNodeDependencies(path, limit);
};

