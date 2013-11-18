"use strict";

const { Cc, Ci, Cu } = require("chrome");
const repo = require("./repo");
const scanner = require("./scanner");
const data = require("self").data;
const systemEvents = require("sdk/system/events");
const windowUtil = require("sdk/window/utils");
const toolbarButton = require("toolbarbutton/toolbarbutton").ToolbarButton;
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");
const Request = require("sdk/request").Request;

let tabTracker = new Map();

exports.tabTracker = tabTracker;
exports.getIdForTabElement = getIdForTabElement;

let button = toolbarButton({
  id: "retire-js-button",
  label: "retire.js",
  tooltiptext: "retirejs",
  image: data.url("icons/icon16.png"),
  onCommand: toggleWebConsole
});

button.moveTo({
  toolbarID: 'nav-bar',
  forceMove: false
});

repo.download().then(() => {
  systemEvents.on("http-on-examine-response", onHttpResponse);
  systemEvents.on("http-on-examine-cached-response", onHttpResponse);
  tabs.on("ready", (tab) => {
    if (/^about:/.test(tab.url)) {
      return;
    }
    tabTracker.get(tab.id).jsSources.forEach((url) => {
      let details = {
        url: url,
        tabId: tab.id
      };
      scanner.scan(details);
    }); 
    console.log("tab ready");
  });
  tabs.on("activate", (tab) => {
    if (tabTracker.has(tab.id)) {
      setBadgeCount(tabTracker.get(tab.id).vulnerableCount);
    } else {
      setBadgeCount(null);
    }
    console.log("activate tab");
  });
  tabs.on("close", (tab) => {
    tabTracker.delete(tab.id);
    console.log("close tab");
  });
});

/**
 * TODO: Check up system/events on() with latest code.
 * The docs are a bit confusing about the arguments.
 * https://addons.mozilla.org/en-US/developers/docs/sdk/latest/modules/sdk/system/events.html
 * https://bugzilla.mozilla.org/show_bug.cgi?id=910599
 */
systemEvents.on("retire-scanner-on-result-ready", (event) => {
  let details = event.subject.details;
  let rmsg = event.subject.msg;
  let tabId = details.tabId;
  tabTracker.get(tabId).vulnerableCount++;
  tabUtil.getTabs().forEach((element) => {
    if (getIdForTabElement(element) == details.tabId) {
      tabUtil.getTabContentWindow(element).console.warn("Loaded library with known vulnerability " + details.url + " See " + rmsg);
    }
  });
  if (tabId == tabs.activeTab.id) {
    setBadgeCount(tabTracker.get(tabId).vulnerableCount);
  }
}, true);

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

function getIdForTabElement(tabElement) {
  return tabElement.getAttribute("linkedpanel").replace(/panel/, "");
}

function onHttpResponse(event) {
  try {
    let channel = event.subject.QueryInterface(Ci.nsIHttpChannel);
    let tabIdForRequest = getIdForTabElement(tabUtil.getTabForContentWindow(getWindowForRequest(event.subject)));
    if (isChannelInitialDocument(channel)) {
      tabTracker.set(tabIdForRequest, {jsSources: [], vulnerableCount: 0});
      setBadgeCount(tabTracker.get(tabIdForRequest).vulnerableCount);
    }
    if (/javascript/.test(channel.getResponseHeader("Content-Type"))) {
      tabTracker.get(tabIdForRequest).jsSources.push(event.subject.URI.spec);
    }
  } catch(e) { 
  }
  return;
}

