/* global require, exports */

var walkdir			= require('walkdir'),
	fs						= require('fs'),
	findYarnWorkspaceRoot = require('find-yarn-workspace-root'),
	lockfile			= require('@yarnpkg/lockfile'),
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
				d.file = "node_modules" + o.dep.dependencies[i].path.split("node_modules").slice(1).join("node_modules") + '/package.json'
			}
			deps.push(d);
			stack.push({parent: d, dep: o.dep.dependencies[i], level: o.level + 1}); 
		}
	}
}

function fetchChildDependencies(path, limit, events) {
	readInstalled(path, {}, function (er, pkginfo) {
		var deps = [];
		if (limit) {
			var packages = JSON.parse(fs.readFileSync(path +'/package.json'));
			filter = [];			

			var filter = packages.dependencies ? Object.keys(packages.dependencies) : [];
			Object.keys(pkginfo.dependencies)
				.filter(function(d) { return !pkginfo.dependencies[d]._requiredBy || pkginfo.dependencies[d]._requiredBy.indexOf("/") > -1;  })
				.filter(function(d) { return filter.indexOf(d) == -1; })
				.forEach(function(d) { delete pkginfo.dependencies[d]; });
		}
		var notInstalled = Object.keys(pkginfo.dependencies).filter(d => !pkginfo.dependencies[d].path);
		if (notInstalled.length > 0) {
			return events.emit('error', 'Could not find dependencies: ' + notInstalled.join(', ') + '. You may need to run npm install');
		}

		listdep({file: 'package.json',component: pkginfo.name, version: pkginfo.version}, pkginfo, 1, deps);
		events.emit('done', deps);				
	});
}

function fetchYarnLockDependencies(lockFileName, events) {
	if (!fs.existsSync(lockFileName)) {
		return events.emit('error', 'Could not find lockfile ' + lockFileName);
	}

	var file = fs.readFileSync(lockFileName, 'utf8');
	var json = lockfile.parse(file);

	if (json.type !== 'success') {
		return events.emit('error', 'Could not parse lockfile ' + lockFileName);
	}

	var result = json.object;
	var deps = Object.keys(result).map(function (key) {
		return {
			module: {
				component: key.split('@')[0],
				version: result[key].version
			},
		};
	});

	events.emit('done', deps);				
}

function fetchPackageLockDependencies(lockFileName, events) {
	if (!fs.existsSync(lockFileName)) {
		return events.emit('error', 'Could not find lockfile ' + lockFileName);
	}

	var file = fs.readFileSync(lockFileName, 'utf8');
	var json = JSON.parse(file);

	var result = json.dependencies;
	var deps = Object.keys(result).map(function (key) {
		return {
			module: {
				component: key,
				version: result[key].version
			},
		};
	});

	events.emit('done', deps);				
}

function getNodeDependencies(path, limit, lockfile) {
	var events = new emitter();

	if (lockfile) {
		if (lockfile === 'npm') {
			fetchPackageLockDependencies(path + '/package-lock.json', events);
		} else if (lockfile === 'yarn') {
			fetchYarnLockDependencies('./yarn.lock', events);
		} else if (lockfile === 'yarn-workspace') {
			var yarnWorkspaceRoot = findYarnWorkspaceRoot();
			var lockFileName = yarnWorkspaceRoot + '/yarn.lock';
			fetchYarnLockDependencies(lockFileName, events);
		}
	} else {
		fetchChildDependencies(path, limit, events);
	}

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

exports.getNodeDependencies = function(path, limit, lockfile) {
	return getNodeDependencies(path, limit, lockfile);
};

