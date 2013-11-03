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
const worker = require("sdk/page-worker");

var repoUrl = "https://raw.github.com/bekk/retire.js/master/repository/jsrepository.json";
var updatedAt = Date.now();
var repo;
var repoFuncs;
var cache = [];
var vulnerable = {};
var tabMap = new Map();
var eventTarget = {};

var button = toolbarButton({
  id: "retire-js",
  label: "retire.js",
  tooltiptext: "retirejs",
  image: data.url("icons/icon16.png"),
  onCommand: () => {
    let tabBrowser = windowUtil.getMostRecentBrowserWindow().gBrowser;
    windowUtil.getMostRecentBrowserWindow().gDevToolsBrowser.selectToolCommand(tabBrowser, "webconsole");
  }
});
button.moveTo({
  toolbarID: 'nav-bar',
  forceMove: false
});

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
  button.badge = {
    text: Number(count) > 0 ? count : "",
    color: 'rgb(193, 56, 50)'
  }
}

function getWindowForRequest(request){
  if (request instanceof Ci.nsIRequest) {
    try {
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

function isChannelInitialDocument(httpChannel) {
  return httpChannel.loadFlags & httpChannel.LOAD_INITIAL_DOCUMENT_URI;
}

events.on(eventTarget, "scan", (details) => {
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

  var results = retire.scanUri(details.url, repo);
  console.log("scanUri: " + results.length + ", "  + details.url);
  if (results.length > 0) {
    events.emit(eventTarget, "result-ready", details, results);
    return;
  }

  results = retire.scanFileName(getFileName(details.url), repo);
  console.log("scanFileName: " + results.length + ", "  + details.url);
  if (results.length > 0) {
    events.emit(eventTarget, "result-ready", details, results);
    return;
  }
  download(details.url).then((content) => { 
    events.emit(eventTarget, "script-downloaded", details, content); 
  });
  return;
});

events.on(eventTarget, "script-downloaded", (details, content) => {
  var results = retire.scanFileContent(content, repo, hasher);
  console.log("scanFileContent: " + results.length + ", "  + details.url);
  if (results.length > 0) {
    events.emit(eventTarget, "result-ready", details, results);
    return;
  }
  events.emit(eventTarget, "sandbox", details, content);
});

events.on(eventTarget, "sandbox", (details, content) => {
  var pageWorker = worker.Page({
    contentScriptFile: data.url("sandbox.js"),
    contentURL: data.url("sandbox.html"),
    contentScriptWhen: "end"
  });
  pageWorker.port.emit("detect-version", content, repoFuncs);
  pageWorker.port.on("version-detected", (result) => {
    if (result.version) {
      var results = retire.check(result.component, result.version, repo);
      console.log("version-detected, results: " + results.length + ", "  + details.url);
      events.emit(eventTarget, "result-ready", details, results);
    }
  });
  pageWorker.port.on("done", () => {
    pageWorker.destroy();
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
    events.emit(eventTarget, "log-result", details, rmsg.join(" "));
  }
});

events.on(eventTarget, "log-result", (details, rmsg) => {
  var tabId = details.tabId;
  if (!tabMap.get(tabId)) {
    tabMap.set(tabId, {fileCount: 0});
  }
  tabMap.get(tabId).fileCount++;
  if (tabId == tabs.activeTab.id) {
    setBadgeCount(tabMap.get(tabId).fileCount);
  }
  //Could be sent to a pageWorker instead.
  windowUtil.getMostRecentBrowserWindow().gBrowser.contentWindow.console.warn("Loaded library with known vulnerability " + details.url + " See " + rmsg);
});

function scan(httpEvent) {
  try {   
    var channel = httpEvent.subject.QueryInterface(Ci.nsIHttpChannel);
    var url = httpEvent.subject.URI.spec;
    var tabIdForRequest = tabUtil.getTabForContentWindow(getWindowForRequest(httpEvent.subject)).getAttribute("linkedpanel").replace(/panel/, "");
    if (isChannelInitialDocument(channel)) {
      tabMap.set(tabIdForRequest, {fileCount: 0});
    }
    if (/javascript/.test(channel.getResponseHeader("Content-Type"))) {
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