/* global chrome, console, exports, CryptoJS */

var repoUrl = "http://localhost:8000/jsrepository.json?";
var updatedAt = Date.now();
var repo;
var cache = [];
var vulnerable = {};
var events = new Emitter();

var hasher = {
	sha1 : function(data) {
		return CryptoJS.SHA1(data).toString(CryptoJS.enc.Hex);
	}
};

function download(url) {
	var events = new Emitter();
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function() {
		if (xhr.readyState == 4) {
			if (xhr.status == 200) {
				events.emit('success', xhr.responseText);
			} else {
				console.warn("Got " + xhr.status + " when trying to download " + url);
			}
		}
	};
	xhr.open("GET", url, true);
	xhr.send();
	return events;
}

function downloadRepo() {
	var events = new Emitter();
	console.log("Downloading repo ...");
	updatedAt = Date.now();
	download(repoUrl + updatedAt).on('success', function(repoData) {
		repo = JSON.parse(repoData);
		console.log("Done");
		cache = [];
		vulnerable = {};
		events.emit('success');
	});
	return events;
}

function getFileName(url) {
	var a = document.createElement("a");
	a.href = url;
	return (a.pathname.match(/\/([^\/?#]+)$/i) || [,""])[1];	
}



events.on('scan', function(details) {
	if ((Date.now() - updatedAt) > 1000*60*60*6) {
		downloadRepo().on('success', function() { events.emit('scan', details); });
		return;
	}
	if (cache.indexOf(details.url) > -1) {
		if (vulnerable.hasOwnProperty(details.url)) {
			events.emit('result-ready', details, vulnerable[details.url]);
		}
		return;
	}
	cache.push(details.url);
	console.log("Scanning " + details.url + " ...");
	var results = exports.scanUri(details.url, repo);
	if (results.length > 0) {
		events.emit('result-ready', details, results);
		return;
	}
	results = exports.scanFileName(getFileName(details.url), repo);
	if (results.length > 0) {
		events.emit('result-ready', details, results);
		return;
	}
	download(details.url).on('success', function(content) { events.emit('script-downloaded', details, content); });
	return;
});

events.on('script-downloaded', function(details, content) {
	var results = exports.scanFileContent(content, repo, hasher);
	if (results.length > 0) {
		events.emit('result-ready', details, results);
		return;
	}
	console.log(hasher.sha1(content) + " : " + details.url);
});


events.on('result-ready', function(details, results) {
	if (exports.isVulnerable(results)) {
		vulnerable[details.url] = results;
		console.warn(details.url, results);
		var rmsg = [];
		for (var i in results) {
			rmsg = rmsg.concat(results[i].vulnerabilities);
		}
		chrome.browserAction.setBadgeText({text : "!", tabId : details.tabId });
		setTimeout(function() {
			chrome.tabs.sendMessage(details.tabId, {
				message : "Loaded library with known vulnerability " + details.url + " See " + rmsg.join(" ")
			});
		}, 3000);
	} else {
		console.log(details.url, results);
	}
});


chrome.browserAction.setBadgeBackgroundColor({ color: [255, 0, 0, 255] });
chrome.runtime.onMessage.addListener(function (request, sender) {
	if (request.count){
		chrome.browserAction.setBadgeText({text : "" + request.count, tabId : sender.tab.id });
	}
});

downloadRepo().on('success', function() {
	var filter = {
		"urls"  : ["<all_urls>"],
		"types" : ["script"]
	};
	function scan(details) {
		if (details.method === "GET") {
			events.emit('scan', details);
		}
		return;
	}
	chrome.webRequest.onCompleted.addListener(scan, filter, []);
});

