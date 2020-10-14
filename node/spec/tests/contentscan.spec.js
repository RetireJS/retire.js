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

describe('content scan', function() {
	it('should_be_vulnerable_between', function(done) {
		var result = retire.scanFileContent("/*! jQuery v1.8.1 asdasd ", repo, hasher);
		assert.isVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_before', function(done) {
		var result = retire.scanFileContent("/*! jQuery v1.6.1 asdasd ", repo, hasher);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_at', function(done) {
		var result = retire.scanFileContent("/*! jQuery v1.9.0 asdasd ", repo, hasher);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_not_be_vulnerable_above', function(done) {
		var result = retire.scanFileContent("/*! jQuery v1.9.1 asdasd ", repo, hasher);
		assert.isNotVulnerable(result);
		done();
	});
	it('should_be_vulnerable_before', function(done) {
		var result = retire.scanFileContent("/*! jQuery v1.4 asdasd ", repo, hasher);
		assert.isVulnerable(result);
		done();
	});
	it('should_be_vulnerable_before_prolog', function(done) {
		var result = retire.scanFileContent("var a = 1; /*! jQuery v1.4 asdasd ", repo, hasher);
		assert.isVulnerable(result);
		done();
	});
});
