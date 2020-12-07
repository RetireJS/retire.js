/* global require, exports */

var walkdir			= require('walkdir'),
	fs						= require('fs'),
	readInstalled	= require('read-installed'),
	emitter				= require('events').EventEmitter;


function listdep(parent, dep, level, deps) {
	var stack = [];
	var dedup = {};
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
			var id = i + "@" + o.dep.dependencies[i].version;
			if (dedup[id]) continue;
			dedup[id] = true;
			var d = { 
				module: { component: i, version: o.dep.dependencies[i].version }
			};
			if (o.dep.dependencies[i].path) {
				d.file = "node_modules" + o.dep.dependencies[i].path.split("node_modules").slice(1).join("node_modules") + '/package.json';
			}
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
				.filter(function(d) { return !pkginfo.dependencies[d]._requiredBy || pkginfo.dependencies[d]._requiredBy.indexOf("/") > -1 || pkginfo.dependencies[d]._requiredBy.indexOf("#DEV:/") > -1;  })
				.filter(function(d) { return filter.indexOf(d) == -1; })
				.forEach(function(d) { delete pkginfo.dependencies[d]; });
		}
		var notInstalled = Object.keys(pkginfo.dependencies).filter(function (d) {
			return !pkginfo.dependencies[d].path;
		});
		if (notInstalled.length > 0) {
			return events.emit('error', 'Could not find dependencies: ' + notInstalled.join(', ') + '. You may need to run npm install');
		}
		listdep({file: 'package.json',component: pkginfo.name, version: pkginfo.version}, pkginfo, 1, deps);
		events.emit('done', deps);				
	});
	return events;
}

function scanJsFiles(path) {
	var finder = walkdir.find(path, { "follow_symlinks" : false, "no_return": true });
	function onFile(file){
		if (file.match(/\.js$/)) {
			finder.emit('jsfile', file);
		}
		if (file.match(/\/bower.json$/)) {
			finder.emit('bowerfile', file);
		}
	}
	finder.on('file', onFile);
	finder.on('link', function(link) {		
		if (fs.existsSync(link)) {
			var file = fs.realpathSync(link);
			if (fs.lstatSync(file).isFile()) {
				onFile(link);
			}
		} else {
			console.log('Could not follow symlink: ' + link);
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

