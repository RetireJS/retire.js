/* global require, exports */

var walkdir			= require('walkdir'),
	fs				= require('fs'),
	readInstalled	= require('read-installed'),
	emitter			= require('events').EventEmitter;


function listdep(parent, filter, dep, level, deps) {
	var stack = [];
	stack.push({parent: parent, filter: filter, dep: dep, level: level}); 
	while ((o = stack.pop()) != null) {
		for (var i in o.dep.dependencies) {
			if (o.filter !== null && o.filter.indexOf(i) == -1) {
				continue;
			}
			cyclic = false;
			dep_parent = o.parent;
			while (dep_parent != null) {
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
			var d = { component: i, version: o.dep.dependencies[i].version, parent: o.parent, level: o.level };
			deps.push(d);
			stack.push({parent: d, filter: null, dep: o.dep.dependencies[i], level: o.level + 1}); 
		}
	}
}

function getNodeDependencies(path, limit) {
	var events = new emitter();
	readInstalled(path, {}, function (er, pkginfo) {
		var deps = [];
		var filter = null;
		if (limit) {
			var packages = JSON.parse(fs.readFileSync(path +'/package.json'));
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

