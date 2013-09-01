var exports = exports || {};
exports.version = '0.1.0';

function isDefined(o) {
	return typeof o !== 'undefined';
}

function scan(data, extractor, repo) {
	for (var component in repo) {
		var extractors = repo[component].extractors[extractor];
		if (!isDefined(extractors)) continue;
		for (var i in extractors) {
			var re = new RegExp(extractors[i]);
			var match = re.exec(data);
			if (match) return { version: match[1], component: component };
		}
	}
	return null;	
}
function scanhash(hash, repo) {
	for (var component in repo) {
		var hashes = repo[component].extractors.hashes;
		if (!isDefined(hashes)) continue;
		for (var i in hashes) {
			if (i === hash) return { version: hashes[i], component: component };
		}
	}
	return null;	
}



function check(result, repo) {
	if (result === null) return null;
	var vulns = repo[result.component].vulnerabilities;
	for (var i in vulns) {
		if (!isAtOrAbove(result.version, vulns[i].below)) {
			if (isDefined(vulns[i].atOrAbove) && !isAtOrAbove(result.version, vulns[i].atOrAbove)) {
				continue;
			}
			result.vulnerabilities = vulns[i].info;
			return result;
		}
	}
	return null;
}

function isAtOrAbove(version1, version2) {
	var v1 = version1.split(/[\.\-]/g);
	var v2 = version2.split(/[\.\-]/g);
	var l = v1.length > v2.length ? v1.length : v2.length;
	for (var i = 0; i < l; i++) {
		if (toComparable(v1[i]) > toComparable(v2[i])) return true;
		if (toComparable(v1[i]) < toComparable(v2[i])) return false;		
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
	if (result === null) {
		result = scanhash(hasher.sha1(content), repo);
	}
	return check(result, repo);
};

exports.scanNodeDependency = function(dependency, npmrepo) {
	return check(dependency, npmrepo);
};

