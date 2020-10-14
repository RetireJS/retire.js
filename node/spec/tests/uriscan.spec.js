var fs     = require("fs"),
	assert = require("../assert"),
	retire = require("../../lib/retire");

var data = fs.readFileSync("spec/repository.json");
var repo = JSON.parse(data);

describe("url scan", function() {
	it('should_be_vulnerable_between', function(done) {
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.8.1/jquery.min.js", repo);
		assert.isVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_before', function(done) {
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_at', function(done) {
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_above', function(done) {
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_be_vulnerable_before', function(done) {
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js", repo);
		assert.isVulnerable(result);
		done();
	});
});
