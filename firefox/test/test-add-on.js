const { Cc, Ci, Cu } = require("chrome");
const repo = require("./repo");
const main = require("./main");
const windowUtil = require("sdk/window/utils");
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");
const promise = require("sdk/core/promise");
const timers = require("sdk/timers");
const tools = Cu.import("resource://gre/modules/devtools/Loader.jsm", {}).devtools;
const TargetFactory = tools.TargetFactory;

let httpServer = createServer();
httpServer.start(-1);

let tab1 = tabs.activeTab;
let tab2 = null;

exports["test add-on"] = function(assert, done) {
  assert.ok(getToolbarButtonEl() != null, "Retire toolbarbutton should exist");
  repo.download().then(() => {
    createTabAndMakeRequest(assert)
      .then(waitForScanner)
      .then(test_toolbarbuttonBadgeShouldShowVulnerableCount)
      .then(test_toolbarbuttonShouldOpenWebConsole)
      .then(test_thereShouldBeSixEntriesInWebConsoleLog)
      .then(activateTab1)
      .then(test_toolbarbuttonBadgeShouldBeHidden)
      .then(activateTab2)
      .then(test_toolbarbuttonBadgeShouldBeVisible)
      .then(() => {
        httpServer.stop(done);
      });
  });
};

function test_toolbarbuttonBadgeShouldShowVulnerableCount(assert) {
  let deferred = promise.defer();
  assert.equal(getToolbarButtonBadgeEl().textContent, "6", "Toolbar button badge should show 6 vulnerable sources");
  deferred.resolve(assert);
  return deferred.promise;
}

function test_toolbarbuttonBadgeShouldBeHidden(assert) {
  let deferred = promise.defer();
  assert.equal(getToolbarButtonBadgeEl().style.display, "none", "Toolbar button badge should be hidden");
  deferred.resolve(assert);
  return deferred.promise;
}

function test_toolbarbuttonBadgeShouldBeVisible(assert) {
  let deferred = promise.defer();
  assert.equal(getToolbarButtonBadgeEl().style.display, "", "Toolbar button badge should be visible");
  deferred.resolve(assert);
  return deferred.promise;
}

function test_toolbarbuttonShouldOpenWebConsole(assert) {
  let deferred = promise.defer();
  getToolbarButtonEl().doCommand();
  getWebConsolePanel().then((panel) => {
    let warningEntries = panel.hud.outputNode.querySelectorAll(".webconsole-msg-console.webconsole-msg-warn");
    assert.ok(panel.isReady, "Button command should activate devtools web console");
    assert.equal(warningEntries.length, 6, "There should be 6 warnings in the web console");
    deferred.resolve(assert);
  });
  return deferred.promise;
}

function test_thereShouldBeSixEntriesInWebConsoleLog(assert) {
  let deferred = promise.defer();
  getWebConsolePanel().then((panel) => {
    let warningEntries = panel.hud.outputNode.querySelectorAll(".webconsole-msg-console.webconsole-msg-warn");
    assert.equal(warningEntries.length, 6, "There should be 6 warnings in the web console");
    deferred.resolve(assert);
  });
  return deferred.promise;
}

function createTabAndMakeRequest(assert) {
  let deferred = promise.defer();
  tabs.open({ 
    url: "http://localhost:" + httpServer.identity.primaryPort + "/test/web/index.html",
    onReady: () => {
      tab2 = tabs.activeTab;
      deferred.resolve(assert);
    }
  });
  return deferred.promise;
}

function waitForScanner(assert) {
  let deferred = promise.defer();
  timers.setTimeout(() => {
    deferred.resolve(assert);
  }, 500);
  return deferred.promise;
}

function activateTab1(assert) {
  let deferred = promise.defer();
  tab1.activate();
  timers.setTimeout(() => {
    deferred.resolve(assert);
  }, 300);
  return deferred.promise;
}

function activateTab2(assert) {
  let deferred = promise.defer();
  tab2.activate();
  timers.setTimeout(() => {
    deferred.resolve(assert);
  }, 300);
  return deferred.promise;
}

function getWebConsolePanel() {
  let deferred = promise.defer();
  timers.setTimeout(() => {
    let gDevTools = windowUtil.getMostRecentBrowserWindow().gDevTools;  
    let tabElement = tabUtil.getActiveTab(windowUtil.getMostRecentBrowserWindow());
    let target = TargetFactory.forTab(tabElement);
    let toolbox = gDevTools.getToolbox(target);
    deferred.resolve(toolbox.getPanel("webconsole"));
  }, 300);
  return deferred.promise;
}

function getToolbarButtonEl() {
  let win = windowUtil.getMostRecentBrowserWindow();
  let button = win.document.getElementById("retire-js-button");
  return button;
}

function getToolbarButtonBadgeEl() {
  return getToolbarButtonEl().querySelector("div");
}

function createServer() {
  let { nsHttpServer } = require("sdk/test/httpd");
  let server = new nsHttpServer();
  let directoryService = Cc["@mozilla.org/file/directory_service;1"]
                   .getService(Ci.nsIProperties);
  let path = directoryService.get("CurWorkD", Ci.nsILocalFile);

  server.registerDirectory("/", path);
  
  //const SERVER_PORT = server.identity.primaryPort;
  return server;
}

require("sdk/test").run(exports);