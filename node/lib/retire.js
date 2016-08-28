/* 
 * This file is used by the browser plugins and the Cli scanner and thus 
 * cannot have any external dependencies (no require)	
 */


var exports = exports || {};
exports.version = '1.2.1';

function isDefined(o) {
	return typeof o !== 'undefined';
}

function scan(data, extractor, repo, matcher) {
	matcher = matcher || simpleMatch;
	var detected = [];
	for (var component in repo) {
		var extractors = repo[component].extractors[extractor];
		if (!isDefined(extractors)) continue;
		for (var i in extractors) {
			var match = matcher(extractors[i], data);
			if (match) detected.push({ version: match, component: component, detection: extractor });
		}
	}
	return detected;
}

function simpleMatch(regex, data) {
	var re = new RegExp(regex);
	var match = re.exec(data);
	return match ? match[1] : null;
}
function replacementMatch(regex, data) {
	var ar = /^\/(.*[^\\])\/([^\/]+)\/$/.exec(regex);
	var re = new RegExp("(" + ar[1] + ")");
	var match = re.exec(data);
	var ver = null;
	if (match) {
		ver = match[1].replace(new RegExp(ar[1]), ar[2]);
		return ver;
	}
	return null;
}


function scanhash(hash, repo) {
	for (var component in repo) {
		var hashes = repo[component].extractors.hashes;
		if (!isDefined(hashes)) continue;
		for (var i in hashes) {
			if (i === hash) return [{ version: hashes[i], component: component, detection: 'hash' }];
		}
	}
	return [];
}



function check(results, repo) {
	for (var r in results) {
		var result = results[r];
		if (!isDefined(repo[result.component])) continue;
		var vulns = repo[result.component].vulnerabilities;
		for (var i in vulns) {
			if (!isAtOrAbove(result.version, vulns[i].below)) {
				if (isDefined(vulns[i].atOrAbove) && !isAtOrAbove(result.version, vulns[i].atOrAbove)) {
					continue;
				}
				var vulnerability = { info : vulns[i].info };
				if (vulns[i].severity) {
					vulnerability.severity = vulns[i].severity;
				}
				if (vulns[i].identifiers) {
					vulnerability.identifiers = vulns[i].identifiers;
				}
				result.vulnerabilities = result.vulnerabilities || [];
				result.vulnerabilities.push(vulnerability);
			}
		}
	}
	return results;
}

function unique(ar) {
	var r = [];
	ar.forEach(function(e) { 
		if (r.indexOf(e) == -1) r.push(e);
	});
	return r;
}


function isAtOrAbove(version1, version2) {
	var v1 = version1.split(/[\.\-]/g);
	var v2 = version2.split(/[\.\-]/g);
	var l = v1.length > v2.length ? v1.length : v2.length;
	for (var i = 0; i < l; i++) {
		var v1_c = toComparable(v1[i]);
		var v2_c = toComparable(v2[i]);
		if (typeof v1_c !== typeof v2_c) return typeof v1_c === 'number';
		if (v1_c > v2_c) return true;
		if (v1_c < v2_c) return false;
	}
	return true;
}

function toComparable(n) {
	if (!isDefined(n)) return 0;
	if (n.match(/^[0-9]+$/)) {
		return parseInt(n, 10);
	}
	return n;
}


//------- External API -------

exports.check = function(component, version, repo) {
	return check([{component: component, version: version}], repo);
};

exports.replaceVersion = function(jsRepoJsonAsText) {
	return jsRepoJsonAsText.replace(/§§version§§/g, '[0-9][0-9.a-z_\\\\-]+');
};

exports.isVulnerable = function(results) {
	for (var r in results) {
		if (results[r].hasOwnProperty('vulnerabilities')) return true;
	}
	return false;
};

exports.scanUri = function(uri, repo) {
	var result = scan(uri, 'uri', repo);
	return check(result, repo);
};

exports.scanFileName = function(fileName, repo) {
	var result = scan(fileName, 'filename', repo);
	return check(result, repo);
};

exports.scanFileContent = function(content, repo, hasher) {
	var result = scan(content, 'filecontent', repo);
	if (result.length === 0) {
		result = scan(content, 'filecontentreplace', repo, replacementMatch);
	}
	if (result.length === 0) {
		result = scanhash(hasher.sha1(content), repo);
	}
	return check(result, repo);
};

exports.scanNodeDependency = function(dependency, npmrepo) {
	if (!isDefined(dependency.version)) {
		console.warn('Missing version for ' + dependency.component + '. Need to run npm install ?');
		return [];
	}
	if (!isDefined(npmrepo[dependency.component])) return [];
	return check([dependency], npmrepo);
};



