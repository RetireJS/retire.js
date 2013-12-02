"use strict";

const { Cc, Ci, Cu } = require("chrome");
const windowUtil = require("sdk/window/utils");
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");

exports.getWindowForRequest = (request) => {
  return getWindowForRequest(request);
}

exports.getBrowserTabElement = (tabId) => {
  return getBrowserTabElement(tabId);
}

exports.getIdForTabElement = (tabElement) => {
  return getIdForTabElement(tabElement);
}

exports.logToWebConsole = (rmsg, details, windowId) => {
  return logToWebConsole(rmsg, details, windowId);
}

exports.toggleWebConsole = () => {
  return toggleWebConsole();
}

// Fixme: make re-usable.
function logToWebConsole(rmsg, details, windowId) {
  // Use nsIScriptError interface
  // This can be replaced with devtools apis when the apis are ready.
  // See: https://bugzilla.mozilla.org/show_bug.cgi?id=843004.
  let consoleService = Cc["@mozilla.org/consoleservice;1"]
      .getService(Ci.nsIConsoleService);
  let scriptError = Cc["@mozilla.org/scripterror;1"]
      .createInstance(Ci.nsIScriptError);
  let category = "Mixed Content Blocker"; // Use a security category. See comment above.
  let logMessage = "Loaded library with known vulnerability " + details.url + "\nSee this " + rmsg;

  scriptError.initWithWindowID(logMessage, details.url, null, null, null, scriptError.warningFlag, category, windowId);
  consoleService.logMessage(scriptError);
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

function getBrowserTabElement(tabId) {
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

