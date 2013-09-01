/* global chrome, console, exports, CryptoJS */

var filter = {
	"urls"  : ["<all_urls>"],
	"types" : ["script"]
};


var opt_extraInfoSpec = [];

function download(url, callback) {
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function() {
		if (xhr.readyState == 4) {
			callback(xhr.responseText);
		}
	};
	xhr.open("GET", url, true);
	xhr.send();
}



chrome.browserAction.setBadgeBackgroundColor({ color: [255, 0, 0, 255] });
chrome.runtime.onMessage.addListener(function (request, sender) {
	if (request.count){
		chrome.browserAction.setBadgeText({text : "" + request.count, tabId : sender.tab.id });
	}
});
var updatedAt = Date.now();
var repo;
var cache = [];
var vulnerable = {};

function downloadRepo(cb) {
	console.log("Downloading repo ...");
	updatedAt = Date.now();
	download("http://erlend.oftedal.no/blog/repository.json?" + updatedAt, function(repoData) {
		repo = JSON.parse(repoData);
		console.log("Done");
		cache = [];
		vulnerable = {};
		cb();
	});
}


downloadRepo(function() {
	function scan(details) {
		if ((Date.now() - updatedAt) > 1000*60*60*6) {
			downloadRepo(function() { scan(details); });
			return;
		}

		function handleResults(results) {
			if (exports.isVulnerable(results)) {
				vulnerable[details.url] = results;
				console.warn(details.url, results);
				var rmsg = [];
				for (var i in results) {
					rmsg = rmsg.concat(results[i].vulnerabilities);
				}
				chrome.browserAction.setBadgeText({text : "!", tabId : details.tabId });
				chrome.tabs.sendMessage(details.tabId, {
					message : "Loaded library with known vulnerability " + details.url +
						" See " + rmsg.join(" ")
				});
			} else {
				console.log(details.url, results);
			}

		}
		if (cache.indexOf(details.url) > -1) {
			if (vulnerable.hasOwnProperty(details.url)) {
				handleResults(vulnerable[details.url]);
			}
			return;
		}
		if (details.method !== "GET") return;
		cache.push(details.url);
		console.log("Scanning " + details.url + " ...");
		var results = exports.scanUri(details.url, repo);
		if (results.length > 0) {
			handleResults(results);
			return;
		}
		var a = document.createElement("a");
		a.href = details.url;
		var fileName = (a.pathname.match(/\/([^\/?#]+)$/i) || [,""])[1];
		results = exports.scanFileName(fileName, repo);
		if (results.length > 0) {
			handleResults(results);
			return;
		}
		download(details.url, function(data) {
			var results = exports.scanFileContent(data, repo, { sha1 : CryptoJS.SHA1 });
			if (results.length > 0) {
				handleResults(results);
				return;
			}
		});
		return;
	}
	chrome.webRequest.onCompleted.addListener(scan, filter, opt_extraInfoSpec);
});

