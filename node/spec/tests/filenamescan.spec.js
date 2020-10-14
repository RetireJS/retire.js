var fs     = require("fs"),
	assert = require("../assert"),
	retire = require("../../lib/retire");

var data = fs.readFileSync("spec/repository.json");
var repo = JSON.parse(data);

describe("filename scan", function() {
	it("should_be_vulnerable_between", function(done) {
		var result = retire.scanFileName("jquery-1.8.1.js", repo);
		assert.isVulnerable(result);
		done();
	});
	it("should_not_be_vulnerable_before", function(done) {
		var result = retire.scanFileName("jquery-1.6.1.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it("should_not_be_vulnerable_at", function(done) {
		var result = retire.scanFileName("jquery-1.9.0.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it("should_not_be_vulnerable_above", function(done) {
		var result = retire.scanFileName("jquery-1.9.1.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it("should_be_vulnerable_before", function(done) {
		var result = retire.scanFileName("jquery-1.4.js", repo);
		assert.isVulnerable(result);
		done();
	});
	it("should_not_be_vulnerable_at_final", function(done) {
		var result = retire.scanFileName("jquery-1.6.0.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it("should_be_vulnerable_at_rc", function(done) {
		var result = retire.scanFileName("jquery-1.6.0-rc.1.js", repo);
		assert.isVulnerable(result);
		done();
	});
	it("should_not_be_vulnerable_at_patched_rc", function(done) {
		var result = retire.scanFileName("jquery-1.6.0-rc.1.1.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
});