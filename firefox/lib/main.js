"use strict";

const { Cc, Ci, Cu } = require("chrome");
const repo = require("./repo");
const scanner = require("./scanner");
const data = require("self").data;
const systemEvents = require("sdk/system/events");
const windows = require("sdk/windows").browserWindows;
const windowUtil = require("sdk/window/utils");
const toolbarButton = require("toolbarbutton/toolbarbutton").ToolbarButton;
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");
const Request = require("sdk/request").Request;

let tabInfo = new Map();

exports.tabInfo = tabInfo;
exports.getIdForTabElement = getIdForTabElement;

let button = toolbarButton({
  id: "retire-js-button",
  label: "retire.js",
  tooltiptext: "Retire.js",
  image: data.url("icons/icon16.png"),
  onCommand: toggleWebConsole
});

button.moveTo({
  toolbarID: 'nav-bar',
  forceMove: false
});

function updateButton(vulnerableCount) {
  let count = Number(vulnerableCount);
  let tooltipText = "Retire.js";
  if (count > 0) {
    tooltipText += "\n" + count + " vulnerable librar" + (count > 1 ? "ies" : "y") +
                   " detected.\nPress button for more info.";
  }
  button.badge = {
    text: count,
    color: "rgb(193, 56, 50)"
  };
  button.tooltiptext = tooltipText;
}

function getTabElement(tabId) {
  let allTabs = tabUtil.getTabs();
  for (let i = 0; i < allTabs.length; i++) {
    if (getIdForTabElement(allTabs[i]) == tabId) {
      return allTabs[i];
    }
  }
  return null;
}

function getIdForTabElement(tabElement) {
  return tabElement.getAttribute("linkedpanel").replace(/panel/, "");
}

function toggleWebConsole() {
  let { gBrowser, gDevToolsBrowser } = windowUtil.getMostRecentBrowserWindow();
  gDevToolsBrowser.selectToolCommand(gBrowser, "webconsole");
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

function tabReadyListener(tab) {
  // about:xx resources should not be scanned.
  if (/^about:/.test(tab.url)) {
    return;
  }
  let tabId = tab.id;
  tabInfo.get(tabId).jsSources.forEach((url) => {
    let details = {
      url: url,
      tabId: tab.id
    };
    scanner.scan(details);
  });
  // Add an unload listener to the tab's page in order to handle back/forward cache (bfCache)
  tabUtil.getTabContentWindow(getTabElement(tabId)).addEventListener("unload", () => {
    if (tabs.activeTab.id == tabId) {
      updateButton(null);
    }
  });
  console.log("tab ready");
}

function tabActivateListener() {
  // Get the active tab id for the window that is in front.
  let tabId = getIdForTabElement(tabUtil.getActiveTab(windowUtil.getMostRecentBrowserWindow()));
  if (tabInfo.has(tabId)) {
    updateButton(tabInfo.get(tabId).vulnerableCount);
  } else {
    updateButton(null);
  }
  console.log("tab activate");
}

function tabCloseListener(tab) {
  tabInfo.delete(tab.id);
  console.log("tab close: " + tab.id);
}

function httpResponseListener(event) {
  try {
    let channel = event.subject.QueryInterface(Ci.nsIHttpChannel);
    let tabIdForRequest = getIdForTabElement(tabUtil.getTabForContentWindow(getWindowForRequest(event.subject)));
    
    if (isChannelInitialDocument(channel)) {
      tabInfo.set(tabIdForRequest, {jsSources: [], vulnerableCount: 0});
      // Start updating the badge if the request is initiated from the active tab.
      if (tabs.activeTab.id == tabIdForRequest) {
        updateButton(tabInfo.get(tabIdForRequest).vulnerableCount);
      }
    }
    if (/javascript/.test(channel.getResponseHeader("Content-Type"))) {
      let requestedUri = event.subject.URI.spec;
      if (repo.dontCheck(requestedUri)) {
        return;
      }
      tabInfo.get(tabIdForRequest).jsSources.push(requestedUri);
    }
  } catch(e) { 
  }
  return;
}

function isChannelInitialDocument(httpChannel) {
  return httpChannel.loadFlags & httpChannel.LOAD_INITIAL_DOCUMENT_URI;
}

repo.download().then(() => {
  systemEvents.on("http-on-examine-response", httpResponseListener);
  systemEvents.on("http-on-examine-cached-response", httpResponseListener);
  windows.on("activate", () => {
    if (tabInfo.has(tabs.activeTab.id)) {
      updateButton(tabInfo.get(tabs.activeTab.id).vulnerableCount);
    }
  });
  tabs.on("ready", tabReadyListener);
  tabs.on("activate", tabActivateListener);
  tabs.on("close", tabCloseListener);
});

function logToWebConsole(rmsg, details, windowId) {
  // Use nsIScriptError interface
  // This can be replaced with devtools apis when the apis are ready.
  // See: https://bugzilla.mozilla.org/show_bug.cgi?id=843004.
  let consoleService = Cc["@mozilla.org/consoleservice;1"]
      .getService(Ci.nsIConsoleService);
  let scriptError = Cc["@mozilla.org/scripterror;1"]
      .createInstance(Ci.nsIScriptError);
  let category = "Mixed Content Blocker"; // Use a security category. See comment above.
  let logMessage = "Loaded library with known vulnerability " + details.url + " See this " + rmsg;

  scriptError.initWithWindowID(logMessage, details.url, null, null, null, scriptError.warningFlag, category, windowId);
  consoleService.logMessage(scriptError);
}
/**
 * TODO: Check up system/events on() with latest code.
 * The docs are a bit off regarding the arguments.
 * https://addons.mozilla.org/en-US/developers/docs/sdk/latest/modules/sdk/system/events.html
 * https://bugzilla.mozilla.org/show_bug.cgi?id=910599
 */
systemEvents.on("retire-scanner-on-result-ready", (event) => {
  let details = event.subject.details;
  let rmsg = event.subject.msg;
  let tabId = details.tabId;
  tabInfo.get(tabId).vulnerableCount++;
  
  logToWebConsole(rmsg, details, windowUtil.getInnerId(tabUtil.getTabContentWindow(getTabElement(tabId))));
  
  if (tabs.activeTab.id == tabId) {
    updateButton(tabInfo.get(tabId).vulnerableCount);
  }
}, true);