/* global chrome, console, exports, CryptoJS, Emitter */

var repoUrl = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";
var updatedAt = Date.now();
var repo;
var repoFuncs;

var vulnerable = {};
var events = new Emitter();
var sandboxWin;
var scanEnabled = true;

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
				console.log("Got " + xhr.status + " when trying to download " + url);
			}
		}
		return true;
	};
	xhr.open("GET", url, true);
	xhr.send();
	return events;
}

function downloadRepo() {
	var events = new Emitter();
	console.log("Downloading repo ...");
	updatedAt = Date.now();
	download(repoUrl + "?" + updatedAt).on('success', function(repoData) {
		repo = JSON.parse(retire.replaceVersion(repoData));
		console.log("Done");
		vulnerable = {};
		setFuncs();
		events.emit('success');
		return true;
	});
	return events;
}

function setFuncs() {
	repoFuncs = {};
	for (var component in repo) {
		if (repo[component].extractors.func) {
			repoFuncs[component] = repo[component].extractors.func;
		}
	}
}

function getFileName(url) {
	var a = document.createElement("a");
	a.href = url;
	return (a.pathname.match(/\/([^\/?#]+)$/i) || [,""])[1];
}



events.on('scan', function(details) {
	if (details.url.indexOf('chrome-extension://') === 0) return true;

	if ((Date.now() - updatedAt) > 1000*60*60*6) {
		downloadRepo().on('success', function() { events.emit('scan', details); });
		return true;
	}
	events.emit('result-ready', details, []);
	console.log("Scanning " + details.url + " ...");
	var results = retire.scanUri(details.url, repo);
	if (results.length > 0) {
		events.emit('result-ready', details, results);
		return true;
	}
	results = retire.scanFileName(getFileName(details.url), repo);
	if (results.length > 0) {
		events.emit('result-ready', details, results);
		return true;
	}
	download(details.url).on('success', function(content) { 
		events.emit('script-downloaded', details, content); 
		return true;
	});
	return true;
});

events.on('script-downloaded', function(details, content) {
	var results = retire.scanFileContent(content, repo, hasher);
	if (results.length > 0) {
		events.emit('result-ready', details, results);
		return true;
	}
	events.emit('sandbox', details, content);
	console.log(hasher.sha1(content) + " : " + details.url);
	return true;
});

events.on('sandbox', function(details, content) {
	sandboxWin.postMessage({ tabId: details.tabId, script : content, url: details.url, repoFuncs: repoFuncs }, "*");
	return true;
});

window.addEventListener("message", function(evt) {
	if (evt.data.version) {
		var results = retire.check(evt.data.component, evt.data.version, repo);
		console.log("SANDBOX", stringifyResults(results));
		events.emit('result-ready', { url : evt.data.original.url, tabId : evt.data.original.tabId }, results);
	}
	return true;
});

function stringifyResults(results) {
	return results.map(x => "\n" + x.component + ":" + x.version).reduce((a,b) => a + b, "");
}

events.on('result-ready', function(details, results) {
	var vulnerable = retire.isVulnerable(results);
	if (vulnerable) {
		console.log(details.url, stringifyResults(results));
		chrome.browserAction.setBadgeText({text : "!", tabId : details.tabId });
	}
	if (!vulnerable) console.log(details.url, stringifyResults(results));

	vulnerable[details.url] = results;
	
	var result = { vulnerable: vulnerable, results: results, url: details.url };
	setTimeout(function() {
		if (details.tabId >= 0) {
			chrome.tabs.sendMessage(details.tabId, {
				message : JSON.stringify(result)
			}, function(response) {
				let e = chrome.runtime.lastError
				if (e) console.log("Failed to send message:" + e);
				console.log(details.tabId);
				if (response) {
					chrome.browserAction.setBadgeText({text : "" + response.count, tabId : details.tabId });
				}
				return true;
			});
		}
		return true;
	}, 3000);
});

chrome.browserAction.setBadgeBackgroundColor({ color: [255, 0, 0, 255] });


chrome.extension.onRequest.addListener(function(request, sender, sendResponse) {
	if (request.to !== 'background') {
		return true;
	}
	if (request.message === 'enabled?') {
		sendResponse({ enabled : scanEnabled });
		return true;
	}
	if (request.message === 'enable') {
		scanEnabled = request.data;
	}
	return true;
});


downloadRepo().on('success', function() {
	var filter = {
		"urls"  : ["<all_urls>"],
		"types" : ["script"]
	};
	function scan(details) {
		if (details.method === "GET" && scanEnabled) {
			events.emit('scan', details);
		}
		return true;
	}
	chrome.webRequest.onCompleted.addListener(scan, filter, []);
	return true;
});

sandboxWin = window.document.getElementById("sandboxframe").contentWindow;





