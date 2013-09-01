var fs       = require("fs"),
	retire   = require("../../lib/retire"),
	assert   = require("../assert"),
	crypto   = require('crypto');

var data = fs.readFileSync("spec/repository.json");
var repo = JSON.parse(data);

var hasher = {
  "sha1" : function(data) {
    shasum   = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  }
};

exports.should_be_vulnerable_between = function(test) {
	var result = retire.scanFileContent("/*! jQuery v1.8.1 asdasd ", repo, hasher);
	assert.isVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_before = function(test) {
	var result = retire.scanFileContent("/*! jQuery v1.6.1 asdasd ", repo, hasher);
	assert.isNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_at = function(test) {
	var result = retire.scanFileContent("/*! jQuery v1.9.0 asdasd ", repo, hasher);
	assert.isNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_above = function(test) {
	var result = retire.scanFileContent("/*! jQuery v1.9.1 asdasd ", repo, hasher);
	assert.isNotVulnerable(test, result);
	test.done();
};
exports.should_be_vulnerable_before = function(test) {
	var result = retire.scanFileContent("/*! jQuery v1.4 asdasd ", repo, hasher);
	assert.isVulnerable(test, result);
	test.done();
};
exports.should_be_vulnerable_before_prolog = function(test) {
	var result = retire.scanFileContent("var a = 1; /*! jQuery v1.4 asdasd ", repo, hasher);
	assert.isVulnerable(test, result);
	test.done();
};
