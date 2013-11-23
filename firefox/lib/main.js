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

function getIdForTabElement(tabElement) {
  return tabElement.getAttribute("linkedpanel").replace(/panel/, "");
}

repo.download().then(() => {
  // Start listening for http responses.
  systemEvents.on("http-on-examine-response", httpResponseListener);
  systemEvents.on("http-on-examine-cached-response", httpResponseListener);
  
  // When the DOM content for a tab is loaded, start scanning the js sources.
  tabs.on("ready", (tab) => {
    // about:xx resources should not be scanned.
    if (/^about:/.test(tab.url)) {
      return;
    }
    // Scan javascript files found in the tab's page.
    tabInfo.get(tab.id).jsSources.forEach((url) => {
      let details = {
        url: url,
        tabId: tab.id
      };
      scanner.scan(details);
    });
    // Add an unload listener to the tab's page in order to handle back/forward cache (bfCache)
    // Also, a tab can be opened in the background so we need to find that tab.
    tabUtil.getTabs().forEach((tabElement) => {
      if (getIdForTabElement(tabElement) == tab.id) {
        tabUtil.getTabContentWindow(tabElement).addEventListener("unload", () => {
          if (tabs.activeTab.id == tab.id) {
            updateButton(null);
          }
        });
      }
    });
    console.log("tab ready");
  });
  // When a tab is activated, update the badge in the toolbarbutton.
  tabs.on("activate", (tab) => {
    // Get the active tab id for the window that is in front.
    let tabId = getIdForTabElement(tabUtil.getActiveTab(windowUtil.getMostRecentBrowserWindow()));
    if (tabInfo.has(tabId)) {
      updateButton(tabInfo.get(tabId).vulnerableCount);
    } else {
      updateButton(null);
    }
    console.log("tab activate");
  });
  windows.on("activate", () => {
    if (tabInfo.has(tabs.activeTab.id)) {
      updateButton(tabInfo.get(tabs.activeTab.id).vulnerableCount);
    }
  });
 
  // Remove the tab info when the tab is closed.
  tabs.on("close", (tab) => {
    tabInfo.delete(tab.id);
    console.log("tab close: " + tab.id);
  });
});


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
  tabUtil.getTabs().forEach((element) => {
    if (getIdForTabElement(element) == details.tabId) {
      tabUtil.getTabContentWindow(element).console.warn("Loaded library with known vulnerability " + details.url + " See " + rmsg);
    }
  });
  if (tabs.activeTab.id == tabId) {
    updateButton(tabInfo.get(tabId).vulnerableCount);
  }
}, true);

