const scanner = require("./scanner");

exports["test getFileName"] = function(assert, done) {
  assert.equal(scanner.getFileName("https://github.com"), "");
  assert.equal(scanner.getFileName("http://github.com/a/b/c/script.js"), "script.js");
  assert.equal(scanner.getFileName("https://github.com/a/b/c/script.js?a=1&b=2&c=3"), "script.js");
  assert.equal(scanner.getFileName("https://github.global.ssl.fastly.net/assets/github-02bcd99101c934d92723526f7e040feda64bb46d.js"), "github-02bcd99101c934d92723526f7e040feda64bb46d.js");
  done();
};

require("sdk/test").run(exports);