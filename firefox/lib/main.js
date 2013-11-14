const { Cc, Ci, Cu } = require("chrome");
const retire = require("./retire");
const sandbox = require("./sandbox");
const hasher = require("./sha1");
const systemEvents = require("sdk/system/events");
const data = require("self").data;
const windowUtil = require("sdk/window/utils");
const URL = require("sdk/url").URL;
const toolbarButton = require("toolbarbutton/toolbarbutton").ToolbarButton;
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");
const events = require("sdk/event/core");
const promise = require("sdk/core/promise");
const XMLHttpRequest = require("sdk/net/xhr").XMLHttpRequest;
const repoUrl = "https://raw.github.com/bekk/retire.js/master/repository/jsrepository.json";

let updatedAt = Date.now();
let repo;
let repoFuncs;
let cache = [];
let vulnerable = {};
let tabInfo = new Map();
let eventTarget = {};
// todo: look into getters
exports.getRepo = function () {
  return repo;
}

let button = toolbarButton({
  id: "retire-js",
  label: "retire.js",
  tooltiptext: "retirejs",
  image: data.url("icons/icon16.png"),
  onCommand: toggleWebConsole
});

button.moveTo({
  toolbarID: 'nav-bar',
  forceMove: false
});

function download(url) {
  let deferred = promise.defer();
  let xhr = new XMLHttpRequest();
  xhr.onreadystatechange = () => {
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

// fixme: If download repo fails, log it and show a warning in the button badge.
function downloadRepo() {
  let deferred = promise.defer();
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
exports.downloadRepo = downloadRepo;

function setFuncs() {
  repoFuncs = {};
  for (let component in repo) {
    if (repo[component].extractors.func) {
      repoFuncs[component] = repo[component].extractors.func;
    }
  }
}

function setBadgeCount(count) {
  button.badge = {
    text: Number(count) > 0 ? count : "",
    color: "rgb(193, 56, 50)"
  }
}

function toggleWebConsole() {
  let { gBrowser, gDevToolsBrowser } = windowUtil.getMostRecentBrowserWindow();
  gDevToolsBrowser.selectToolCommand(gBrowser, "webconsole");
}

function isChannelInitialDocument(httpChannel) {
  return httpChannel.loadFlags & httpChannel.LOAD_INITIAL_DOCUMENT_URI;
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

function getTabElementId(tabElement) {
  return tabElement.getAttribute("linkedpanel").replace(/panel/, "");
}
exports.getTabElementId = getTabElementId;

function getFileName(url) {
  var path = new URL(url).path;
  var filename = (path.match(/[^\/?#]+(?=$|[?#])/) || [""])[0];
  return filename;
}
exports.getFileName = getFileName;

events.on(eventTarget, "scan", (details) => {
  console.log("scan")
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
  let results = retire.scanUri(details.url, repo);
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
  let results = retire.scanFileContent(content, repo, hasher);
  if (results.length > 0) {
    events.emit(eventTarget, "result-ready", details, results);
    return;
  }
  events.emit(eventTarget, "sandbox", details, content);
});

events.on(eventTarget, "sandbox", (details, content) => {
  sandbox.run(content, repoFuncs, eventTarget, details);
});

events.on(eventTarget, "sandbox-version-detected", (result, details) => {
  if (result.version) {
    let results = retire.check(result.component, result.version, repo);
    events.emit(eventTarget, "result-ready", details, results);
  }
});

events.on(eventTarget, "result-ready", (details, results) => {
  console.log("result-ready "+ details.url +", isVulnerable: " + retire.isVulnerable(results));
  if (retire.isVulnerable(results)) {
    vulnerable[details.url] = results;
    let rmsg = [];
    for (let i in results) {
      rmsg = rmsg.concat(results[i].vulnerabilities);
    }
    events.emit(eventTarget, "show-result", details, rmsg.join(" "));
  }
});

events.on(eventTarget, "show-result", (details, rmsg) => {
  let tabId = details.tabId;
  tabInfo.get(tabId).vulnerableCount++;
  tabUtil.getTabs().forEach((element) => {
    if (getTabElementId(element) == details.tabId) {
      tabUtil.getTabContentWindow(element).console.warn("Loaded library with known vulnerability " + details.url + " See " + rmsg);
    }
  })
  if (tabId == tabs.activeTab.id) {
    setBadgeCount(tabInfo.get(tabId).vulnerableCount);
  }
});

function onHttpResponse(event) {
  try {
    let channel = event.subject.QueryInterface(Ci.nsIHttpChannel);
    let tabIdForRequest = getTabElementId(tabUtil.getTabForContentWindow(getWindowForRequest(event.subject)));
    if (isChannelInitialDocument(channel)) {
      tabInfo.set(tabIdForRequest, {jsSources: [], vulnerableCount: 0});
      setBadgeCount(tabInfo.get(tabIdForRequest).vulnerableCount);
    }
    if (/javascript/.test(channel.getResponseHeader("Content-Type"))) {
      tabInfo.get(tabIdForRequest).jsSources.push(event.subject.URI.spec);
    }
  } catch(e) { 
  }
  return;
}

downloadRepo().then(() => {
  systemEvents.on("http-on-examine-response", onHttpResponse);
  systemEvents.on("http-on-examine-cached-response", onHttpResponse);

  tabs.on("ready", (tab) => {
    if (/^about:/.test(tab.url)) {
      return;
    }
    tabInfo.get(tab.id).jsSources.forEach((url) => {
      let details = {
        url: url,
        tabId: tab.id
      };
      events.emit(eventTarget, "scan", details);
    }); 
    console.log("tab ready");
  });
  tabs.on("activate", (tab) => {
    if (tabInfo.has(tab.id)) {
      setBadgeCount(tabInfo.get(tab.id).vulnerableCount);
    } else {
      setBadgeCount(null);
    }
    console.log("activate tab");
  });
  tabs.on("close", (tab) => {
    delete tabInfo.delete(tab.id);
    console.log("close tab");
  });
});


