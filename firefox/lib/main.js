"use strict";

const { Cc, Ci } = require("chrome");
const browser = require("./browser");
const repo = require("./repo");
const scanner = require("./scanner");
const data = require("self").data;
const systemEvents = require("sdk/system/events");
const windows = require("sdk/windows").browserWindows;
const windowUtil = require("sdk/window/utils");
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");
const toolbarButton = require("toolbarbutton/toolbarbutton").ToolbarButton;

let tabInfo = new Map();

let button = toolbarButton({
  id: "retire-js-button",
  label: "retire.js",
  tooltiptext: "Retire.js",
  image: data.url("icons/icon16.png"),
  onCommand: browser.toggleWebConsole
});

button.moveTo({
  toolbarID: 'nav-bar',
  forceMove: false
});

repo.download().then(() => {
  systemEvents.on("http-on-examine-response", onExamineResponse);
  systemEvents.on("http-on-examine-cached-response", onExamineResponse);
  systemEvents.on("retirejs:scanner:on-result-ready", onScanResultReady, true);
  windows.on("activate", onActivateWindow);
  tabs.on("activate", onTabActivate);
  tabs.on("ready", onTabReady);
  tabs.on("close", onTabClose);
});

function onScanResultReady(event) {
  let details = event.subject.details;
  let rmsg = event.subject.msg;
  let tabId = details.tabId;
  tabInfo.get(tabId).vulnerableCount++;
  if (tabs.activeTab.id == tabId) {
    updateButton(tabInfo.get(tabId).vulnerableCount);
  }
  browser.logToWebConsole(rmsg, details, windowUtil.getInnerId(tabUtil.getTabContentWindow(browser.getBrowserTabElement(tabId))));
}

function onActivateWindow() {
  if (tabInfo.has(tabs.activeTab.id)) {
    updateButton(tabInfo.get(tabs.activeTab.id).vulnerableCount);
  }
}

function onTabReady(tab) {
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
  
  function onUnload() {
    if (tabs.activeTab.id == tabId) {
      updateButton(null);
      tabUtil.getTabContentWindow(browser.getBrowserTabElement(tabId)).removeEventListener("unload", onUnload);
    }
  }
  
  // Add an unload listener to the tab's page in order to handle back/forward cache (bfCache)
  tabUtil.getTabContentWindow(browser.getBrowserTabElement(tabId)).addEventListener("unload", onUnload);
  console.log("tab ready");
}

function onTabActivate() {
  // Get the active tab id for the window that is in front.
  let tabId = browser.getIdForTabElement(tabUtil.getActiveTab(windowUtil.getMostRecentBrowserWindow()));
  if (tabInfo.has(tabId)) {
    updateButton(tabInfo.get(tabId).vulnerableCount);
  } else {
    updateButton(null);
  }
  console.log("tab activate");
}

function onTabClose(tab) {
  tabInfo.delete(tab.id);
  console.log("tab close: " + tab.id);
}

function updateButton(vulnerableCount) {
  let count = Number(vulnerableCount);
  let tooltipText = "Retire.js";
  if (count > 0) {
    tooltipText += "\n" + count + " vulnerable librar" + (count > 1 ? "ies" : "y") +
                   " detected.";
  }
  button.badge = {
    text: count,
    color: "rgb(193, 56, 50)"
  };
  button.tooltiptext = tooltipText;
}

function isChannelInitialDocument(httpChannel) {
  return httpChannel.loadFlags & httpChannel.LOAD_INITIAL_DOCUMENT_URI;
}

function onExamineResponse(event) {
  try {
    let channel = event.subject.QueryInterface(Ci.nsIHttpChannel);
    let tabIdForRequest = browser.getIdForTabElement(tabUtil.getTabForContentWindow(browser.getWindowForRequest(event.subject)));
    
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
