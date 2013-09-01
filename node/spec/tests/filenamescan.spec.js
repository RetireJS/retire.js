var fs     = require("fs"),
	assert = require("../assert"),
	retire = require("../../lib/retire");

var data = fs.readFileSync("spec/repository.json");
var repo = JSON.parse(data);

exports.should_be_vulnerable_between = function(test) {
	var result = retire.scanFileName("jquery-1.8.1.js", repo);
	assert.isVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_before = function(test) {
	var result = retire.scanFileName("jquery-1.6.1.js", repo);
	assert.isNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_at = function(test) {
	var result = retire.scanFileName("jquery-1.9.0.js", repo);
	assert.isNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_above = function(test) {
	var result = retire.scanFileName("jquery-1.9.1.js", repo);
	assert.isNotVulnerable(test, result);
	test.done();
};
exports.should_be_vulnerable_before = function(test) {
	var result = retire.scanFileName("jquery-1.4.js", repo);
	assert.isVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_at_final = function(test) {
	var result = retire.scanFileName("jquery-1.6.0.js", repo);
	assert.isNotVulnerable(test, result);
	test.done();
};
exports.should_be_vulnerable_at_rc = function(test) {
	var result = retire.scanFileName("jquery-1.6.0-rc.1.js", repo);
	assert.isVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_at_patched_rc = function(test) {
	var result = retire.scanFileName("jquery-1.6.0-rc.1.1.js", repo);
	assert.isNotVulnerable(test, result);
	test.done();
};