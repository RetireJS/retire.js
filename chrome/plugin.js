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
    }
	xhr.open("GET", url, true);
	xhr.send();	
}



chrome.browserAction.setBadgeBackgroundColor({ color: [255, 0, 0, 255] });
chrome.runtime.onMessage.addListener(
	function (request, sender) {
		if (request.count){ 
			chrome.browserAction.setBadgeText({text : "" + request.count, tabId : sender.tab.id }); 
		}
	}

);
var updatedAt = Date.now();
var repo;
var cache = [];
var vulnerable = {};

function downloadRepo(cb) {
	console.log("Downloading repo ...");
	updatedAt = Date.now();
	download('http://erlend.oftedal.no/blog/repository.json?' + updatedAt, function(repoData) {
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
			downloadRepo(function() { scan(details) });
			return;
		}

		function warn(result) {
			chrome.tabs.sendMessage(details.tabId, { 
				message : "Loaded library with known vulnerability " + details.url + 
					" See " + result.vulnerabilities.join(" ") 
			});
		}
		if (cache.indexOf(details.url) > -1) {
			if (vulnerable.hasOwnProperty(details.url)) {
				warn(vulnerable[details.url]);
			}
			return;
		}
		if (details.method !== "GET") return;
		cache.push(details.url);
		console.log("Scanning " + details.url + " ...");
		var a = document.createElement("a");
		a.href = details.url;
		var fileName = (a.pathname.match(/\/([^\/?#]+)$/i) || [,''])[1];
		var result = exports.scanFileName(fileName, repo);
		if (result != null) {
			vulnerable[details.url] = result;
			warn(result);
			return;
		}
		download(details.url, function(data) {
			var result = exports.scanFileContent(data, repo, { sha1 : CryptoJS.SHA1 });
			if (result != null) {
				vulnerable[details.url] = result;
				warn(result);
			}
		});
		return;
	}
	chrome.webRequest.onCompleted.addListener(scan, filter, opt_extraInfoSpec);
});

