"use strict";

const { Cc, Ci } = require("chrome");
const firefox = require("./firefox");
const repo = require("./repo");
const scanner = require("./scanner");
const data = require("sdk/self").data;
const systemEvents = require("sdk/system/events");
const windows = require("sdk/windows").browserWindows;
const windowUtil = require("sdk/window/utils");
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");
const toolbarButton = require("toolbarbutton/toolbarbutton").ToolbarButton;
const timers = require("sdk/timers");

let tabInfo = new Map();

let button = toolbarButton({
  id: "retire-js-button",
  label: "retire.js",
  tooltiptext: "Retire.js",
  image: data.url("icons/icon16.png"),
  onCommand: firefox.toggleWebConsole
});

button.moveTo({
  toolbarID: 'nav-bar',
  forceMove: false
});

repo.download().then(() => {
  systemEvents.on("http-on-examine-response", onExamineResponse);
  systemEvents.on("http-on-examine-cached-response", onExamineResponse);
  systemEvents.on("http-on-examine-merged-response", onExamineResponse);
  systemEvents.on("retirejs:scanner:on-result-ready", onScanResultReady, true);
  windows.on("activate", onActivateWindow);
  tabs.on("activate", onTabActivate);
  tabs.on("ready", onTabReady);
  tabs.on("close", onTabClose);
  tabs.on("open", (tab) => {
    resetInfoForTab(tab.id);
  });
});

function onScanResultReady(event) {
  let details = event.subject.details;
  let rmsg = event.subject.msg;
  let tabId = details.tabId;
  tabInfo.get(tabId).vulnerableCount++;
  if (tabs.activeTab.id == tabId) {
    updateButton(tabInfo.get(tabId).vulnerableCount);
  }
  firefox.logToWebConsole(rmsg, details, windowUtil.getInnerId(tabUtil.getTabContentWindow(firefox.getBrowserTabElement(tabId))));
}

function onActivateWindow() {
  if (tabInfo.has(tabs.activeTab.id)) {
    updateButton(tabInfo.get(tabs.activeTab.id).vulnerableCount);
  }
}

function onTabReady(tab) {
  if (/^about:/.test(tab.url)) {
    return;
  }

  let tabId = tab.id;
  timers.setTimeout(() => {
    tabInfo.get(tabId).jsSources.forEach((url) => {
      let details = {
        url: url,
        tabId: tabId
      };
      scanner.scan(details);
    });
  }, 1000);
  
  // Add an unload listener to the tab's page in order to reset the button badge on back/forward cache (bfCache)
  function onUnload() {
    if (tabs.activeTab.id == tabId) {
      console.log("unload");
      updateButton(null);
      tabUtil.getTabContentWindow(firefox.getBrowserTabElement(tabId)).removeEventListener("unload", onUnload);
    }
  }
  tabUtil.getTabContentWindow(firefox.getBrowserTabElement(tabId)).addEventListener("unload", onUnload);

  console.log("tab ready: " + tabId);
}

function onTabActivate() {
  // Get the active tab id for the window that is in front.
  let tabId = firefox.getIdForTabElement(tabUtil.getActiveTab(windowUtil.getMostRecentBrowserWindow()));
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

function resetInfoForTab(tabId) {
  tabInfo.set(tabId, {
    jsSources: [], 
    vulnerableCount: 0
  });
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
    let tab = tabUtil.getTabForContentWindow(firefox.getWindowForRequest(event.subject));
    let tabIdForRequest = firefox.getIdForTabElement(tab);
    if (isChannelInitialDocument(channel)) {
      resetInfoForTab(tabIdForRequest);
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

resetInfoForTab(tabs.activeTab.id);
