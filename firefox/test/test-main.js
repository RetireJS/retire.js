const main = require("./main");
const tabs = require("sdk/tabs");
const tabUtil = require("sdk/tabs/utils");
const promise = require("sdk/core/promise");

exports["test downloadRepo"] = function(assert, done) {
  main.downloadRepo().then(() => {
    let repo = main.getRepo();
    assert.ok(repo != null, true);
    assert.ok(Object.keys(repo).length > 0, true);
    done();
  });
};

exports["test getFileName"] = function(assert, done) {
  assert.ok(main.getFileName("https://github.com") == "");
  assert.ok(main.getFileName("http://github.com/a/b/c/script.js") == "script.js");
  assert.ok(main.getFileName("https://github.com/a/b/c/script.js?a=1&b=2&c=3") == "script.js");
  assert.ok(main.getFileName("https://github.global.ssl.fastly.net/assets/github-02bcd99101c934d92723526f7e040feda64bb46d.js") == "github-02bcd99101c934d92723526f7e040feda64bb46d.js");
  done();
};

exports["test getTabElementId"] = function(assert, done) {
  assert.ok(main.getTabElementId(tabUtil.getTabs()[0]), tabs.activeTab.id);
  done();
};

require("sdk/test").run(exports);