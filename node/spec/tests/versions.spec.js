var fs     = require("fs"),
	assert = require("../assert"),
	retire = require("../../lib/retire");

var data = fs.readFileSync("spec/repository.json");
var repo = JSON.parse(data);

describe("versions", function() {
	it('should_not_be_vulnerable_release_when_beta_is', function(done) {
		repo.jquery.vulnerabilities.push({"below":"10.0.0.beta.2"});
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_be_vulnerable_release_when_all_starting_at_version_is', function(done) {
		repo.jquery.vulnerabilities.push({"atOrAbove": "10.0.0-*", "below":"10.0.1"});
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js", repo);
		assert.isVulnerable(result);
		done();
	});

	it('should_not_be_vulnerable_higher_beta_when_beta', function(done) {
		repo.jquery.vulnerabilities = [{"below":"10.0.0.beta.2"}];
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.3/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_rc_when_beta', function(done) {
		repo.jquery.vulnerabilities = [{"below":"1.9.0b1"}];
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.9.0rc1/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_when_at_beta', function(done) {
		repo.jquery.vulnerabilities = [{"below":"10.0.0.beta.2"}];
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_be_vulnerable_when_lower_beta',function(done) {
		repo.jquery.vulnerabilities = [{"below":"10.0.0.beta.2"}];
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js", repo);
		assert.isVulnerable(result);
		done();
	});
	it('should_be_vulnerable_beta_when_below_release', function(done) {
		repo.jquery.vulnerabilities = [{"below":"10.0.0"}];
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js", repo);
		assert.isVulnerable(result);
		done();
	});
	it('should_be_vulnerable_rc_when_below_release', function(done) {
		repo.jquery.vulnerabilities = [{"below":"10.0.0"}];
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", repo);
		assert.isVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_when_is_rc_and_lower_beta',function(done) {
		repo.jquery.vulnerabilities = [{"below":"10.0.0.beta.2"}];
		var result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_see_min_as_at_or_above_non_min_below', function(done) {
		repo.jquery.vulnerabilities = [{"below":"3.5.0"}];
		var result = retire.scanUri("https://ajax.googleapis.com/lib/jquery-3.5.0.min.js", repo);
		assert.isNotVulnerable(result);
		done();
	});
});
