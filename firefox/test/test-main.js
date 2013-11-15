const { Cc, Ci, Cu } = require("chrome");
const main = require("./main");
const windowUtil = require("sdk/window/utils");
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");

exports["test getTabElementId"] = function(assert, done) {
  assert.ok(main.getTabElementId(tabUtil.getTabs()[0]), tabs.activeTab.id);
  done();
};

require("sdk/test").run(exports);