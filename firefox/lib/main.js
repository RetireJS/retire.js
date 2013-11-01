const { Cc, Ci } = require("chrome");
const retire = require("./retire");
const hasher = require("./sha1");
const data = require("self").data;
const promise = require("sdk/core/promise");
const systemEvents = require("sdk/system/events");
const events = require("sdk/event/core");
const toolbarButton = require("toolbarbutton/toolbarbutton").ToolbarButton;
const XMLHttpRequest = require("sdk/net/xhr").XMLHttpRequest;
const tabs = require("sdk/tabs");
const windowUtil = require("sdk/window/utils");
const tabUtil = require("sdk/tabs/utils");
const URL = require("sdk/url").URL;

var eventTarget = {};

var repoUrl = "https://raw.github.com/bekk/retire.js/master/repository/jsrepository.json";
var updatedAt = Date.now();
var repo;
var repoFuncs;
var cache = [];
var vulnerable = {};

function getActiveBrowserWindow() {
    return require("window-utils").activeBrowserWindow;
}

let tbb = toolbarButton({
	id: "retire-js",
	label: "retire.js",
	tooltiptext: "retirejs",
	image: data.url("icons/icon16.png")
});

tbb.moveTo({
	toolbarID: 'nav-bar',
	forceMove: false
});

function download(url) {
	var deferred = promise.defer();
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function() {
		if (xhr.readyState == 4) {
			if (xhr.status == 200) {
				deferred.resolve(xhr.responseText);
			} else {
				console.warn("Got " + xhr.status + " when trying to download " + url);
			}
		}
	};
	xhr.open("GET", url, true);
	xhr.send();

	return deferred.promise;
}

function downloadRepo() {
	var deferred = promise.defer();
    console.log("Downloading repo ...");
    updatedAt = Date.now();
    download(repoUrl + "?" + updatedAt).then((repoData) => {
        repo = JSON.parse(retire.replaceVersion(repoData));
        cache = [];
        vulnerable = {};
        setFuncs();
    	deferred.resolve();
    });

    return deferred.promise;
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
    return new URL(url).path;
}

// There should be better way to do this
function sendMsgToDevToolsConsole(msg) {
    getActiveBrowserWindow().gBrowser.contentWindow.console.warn(msg);
}

events.on(eventTarget, "scan", (details) => {
	console.log("*********** SCAN ***********");
    if ((Date.now() - updatedAt) > 1000*60*60*6) {
        downloadRepo().then(() => { 
            events.emit(eventTarget, "scan", details); 
        });
        return;
    }
    if (cache.indexOf(details.url) > -1) {
        if (vulnerable.hasOwnProperty(details.url)) {
            events.emit(eventTarget, "result-ready", details, vulnerable[details.url]);
        }
        return;
    }
    cache.push(details.url);
    console.log("Scanning " + details.url + " ...");
    var results = retire.scanUri(details.url, repo);
    if (results.length > 0) {
        events.emit(eventTarget,'result-ready', details, results);
        return;
    }
    results = retire.scanFileName(getFileName(details.url), repo);
    if (results.length > 0) {
        events.emit(eventTarget,'result-ready', details, results);
        return;
    }
    download(details.url).then((content) => { 
        console.log("Downloaded: " + details.url); 
        events.emit(eventTarget,'script-downloaded', details, content); 
    });
    return;
});

events.on(eventTarget, "script-downloaded", (details, content) => {
    //fixme: buggy

    var results = retire.scanFileContent(content, repo, hasher);
    console.log("script-downloaded ("+results.length+"): "  + details.url);
    if (results.length > 0) {
        events.emit(eventTarget,"result-ready", details, results);
        return;
    }
});

var count = 0; //fixme: update badge pr. tab

events.on(eventTarget, "result-ready", (details, results) => {
    console.log("result-ready, siVulnerable: " + retire.isVulnerable(results));
    if (retire.isVulnerable(results)) {
        vulnerable[details.url] = results;
        var rmsg = [];
        for (var i in results) {
            rmsg = rmsg.concat(results[i].vulnerabilities);
        }
        sendMsgToDevToolsConsole("Loaded library with known vulnerability " + details.url + " See " + rmsg.join(" "));

        //fixme: update badge pr. tab
        setBadgeCount(count++);
    } else {
        console.log(details.url, results);
    }
});

function scan(event) {
    var channel = event.subject.QueryInterface(Ci.nsIHttpChannel);
    var contentType = channel.getResponseHeader("Content-Type");
    var url = event.subject.URI.spec;
    if (/javascript/.test(contentType)) {
        var details = {
            url: url,
            tabId: tabs.activeTab
        };
        events.emit(eventTarget, "scan", details);
    }
    return;
}

function setBadgeCount(count) {
    tbb.badge = {
        text: count > 0 ? count : "",
        color: 'rgb(65, 131, 196)'
    }
}

downloadRepo().then(function () {
    systemEvents.on("http-on-examine-response", scan);
    systemEvents.on("http-on-examine-cached-response", scan);
});



