const { Cc, Ci, Cu } = require("chrome");
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

var tabMap = new Map();
var eventTarget = {};

var repoUrl = "https://raw.github.com/bekk/retire.js/master/repository/jsrepository.json";

var updatedAt = Date.now();
var repo;
var repoFuncs;
var cache = [];
var vulnerable = {};

// Install 
var tbb = toolbarButton({
    id: "retire-js",
    label: "retire.js",
    tooltiptext: "retirejs",
    image: data.url("icons/icon16.png")
});
tbb.moveTo({
    toolbarID: 'nav-bar',
    forceMove: false
});

// Tab activity
tabs.on("activate", (tab) => {
    if (tabMap.get(tab.id)) {
        setBadgeCount(tabMap.get(tab.id).fileCount);
    } else {
        setBadgeCount("");
    }
});
tabs.on("close", (tab) => {
    delete tabMap.delete(tab.id);
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
        console.log("Repo downloaded");
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

function setBadgeCount(count) {
    tbb.badge = {
        text: Number(count) > 0 ? count : "",
        color: 'rgb(230, 96, 0)'
    }
}

function getWindowForRequest(request){
    if (request instanceof Ci.nsIRequest) {
        try{
            if (request.notificationCallbacks) {
                return request.notificationCallbacks.getInterface(Ci.nsILoadContext).associatedWindow;
            }
        } catch(e) {
        }
        try {
            if (request.loadGroup && request.loadGroup.notificationCallbacks) {
                return request.loadGroup.notificationCallbacks.getInterface(Ci.nsILoadContext).associatedWindow;
            }
        } catch(e) {
        }
    }
    return null;
}

events.on(eventTarget, "scan", (details) => {
	//console.log("*********** SCAN ***********");
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
    //console.log("Scanning " + details.url + " ...");
    var results = retire.scanUri(details.url, repo);
    console.log("scan uri: " + results.length);
    if (results.length > 0) {
        events.emit(eventTarget,'result-ready', details, results);
        return;
    }
    results = retire.scanFileName(getFileName(details.url), repo);
    console.log("scan filename: " + results.length);
    if (results.length > 0) {
        events.emit(eventTarget,'result-ready', details, results);
        return;
    }
    download(details.url).then((content) => { 
        events.emit(eventTarget,'script-downloaded', details, content); 
    });
    return;
});

events.on(eventTarget, "script-downloaded", (details, content) => {
    //fixme: buggy. For some reason the "dojo.js" file reports an error: console[_8] is not defined when eval'ed

    var results = retire.scanFileContent(content, repo, hasher);
    //console.log("script-downloaded, results: " + results.length + ", "  + details.url);
    if (results.length > 0) {
        events.emit(eventTarget, "result-ready", details, results);
        return;
    }

    events.emit(eventTarget, "sandbox", details, content);
});

events.on(eventTarget, "sandbox", (details, content) => {
    var pageWorker = require("sdk/page-worker").Page({
        contentScriptFile: data.url("sandbox.js"),
        contentURL: data.url("sandbox.html"),
        contentScriptWhen: "end"
    });
    pageWorker.port.emit("testScript", content, repoFuncs);
    pageWorker.port.on("result", (result) => {
        if (result.version) {
            var results = retire.check(result.component, result.version, repo);

            events.emit(eventTarget, "result-ready", details, results);
            //events.emit(eventTarget, "result-ready", { url : evt.data.original.url, tabId : evt.data.original.tabId }, results);
        }
    });
});

events.on(eventTarget, "result-ready", (details, results) => {
    console.log("result-ready "+ details.url +", isVulnerable: " + retire.isVulnerable(results));
    if (retire.isVulnerable(results)) {
        vulnerable[details.url] = results;
        var rmsg = [];
        for (var i in results) {
            rmsg = rmsg.concat(results[i].vulnerabilities);
        }
        events.emit(eventTarget, "log", details, rmsg.join(" "));
    } else {
        //console.log(details.url, results);
    }
});

events.on(eventTarget, "log", (details, rmsg) => {
    var tabId = details.tabId;
    if (!tabMap.get(tabId)) {
        tabMap.set(tabId, {fileCount: 0});
    }
    tabMap.get(tabId).fileCount++;
    if (tabId == tabs.activeTab.id) {
        setBadgeCount(tabMap.get(tabId).fileCount);
    }
    windowUtil.getMostRecentBrowserWindow().gBrowser.contentWindow.console.warn("Loaded library with known vulnerability " + details.url + " See " + rmsg);
});

function scan(httpEvent) {
    try {   
        var channel = httpEvent.subject.QueryInterface(Ci.nsIHttpChannel);
        var contentType = channel.getResponseHeader("Content-Type");
        var url = httpEvent.subject.URI.spec;
        if (/javascript/.test(contentType)) {
            console.log("prepeare: " + url);
            var tabIdForRequest = tabUtil.getTabForContentWindow(getWindowForRequest(httpEvent.subject)).getAttribute("linkedpanel").replace(/panel/, "");
            var details = {
                url: url,
                tabId: tabIdForRequest
            };
            events.emit(eventTarget, "scan", details);
        }
    } catch(e) {
    }
    return;
}

downloadRepo().then(function () {
    systemEvents.on("http-on-examine-response", scan);
    systemEvents.on("http-on-examine-cached-response", scan);
});