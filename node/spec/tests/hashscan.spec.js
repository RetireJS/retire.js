var fs       = require("fs"),
	retire   = require("../../lib/retire"),
	crypto   = require('crypto');

var data = fs.readFileSync("spec/repository.json");
var repo = JSON.parse(data);
var content = "data";

var hasher = {
  "sha1" : function(data) {
    shasum   = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  }
};

var hash = hasher.sha1(content);

function assertIsVulnerable(test, result) {
	test.equal(true, typeof result !== 'undefined');
	test.equal(true, result.vulnerability !== null);	
}
function assertIsNotVulnerable(test, result) {
	test.equal(null, result);
}


exports.should_be_vulnerable_between = function(test) {
	repo.jquery.extractors.hashes[hash] = "1.8.1"; 
	var result = retire.scanFileContent(content, repo, hasher);
	assertIsVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_before = function(test) {
	repo.jquery.extractors.hashes[hash] = "1.6.1"; 
	var result = retire.scanFileContent(content, repo, hasher);
	assertIsNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_at = function(test) {
	repo.jquery.extractors.hashes[hash] = "1.9.0"; 
	var result = retire.scanFileContent(content, repo, hasher);
	assertIsNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_above = function(test) {
	repo.jquery.extractors.hashes[hash] = "1.9.1"; 
	var result = retire.scanFileContent(content, repo, hasher);
	assertIsNotVulnerable(test, result);
	test.done();
};
exports.should_be_vulnerable_before = function(test) {
	repo.jquery.extractors.hashes[hash] = "1.4"; 
	var result = retire.scanFileContent(content, repo, hasher);
	assertIsVulnerable(test, result);
	test.done();
};

