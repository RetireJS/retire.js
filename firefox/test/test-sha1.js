const hasher = require("./sha1");

exports["test sha1"] = function(assert, done) {
  assert.ok(hasher.sha1("retire.js"), "6f8d966fb069982a7877e806eef52dac05e49355");
  done();
};

require("sdk/test").run(exports);