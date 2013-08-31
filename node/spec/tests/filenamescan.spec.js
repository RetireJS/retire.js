var fs = require("fs"),
	retire = require("../../lib/retire");

var data = fs.readFileSync("spec/repository.json");
var repo = JSON.parse(data);

function assertIsVulnerable(test, result) {
	test.equal(true, typeof result !== 'undefined');
	test.equal(true, result.vulnerability !== null);	
}
function assertIsNotVulnerable(test, result) {
	test.equal(null, result);
}


exports.should_be_vulnerable_between = function(test) {
	var result = retire.scanFileName("jquery-1.8.1.js", repo);
	assertIsVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_before = function(test) {
	var result = retire.scanFileName("jquery-1.6.1.js", repo);
	assertIsNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_at = function(test) {
	var result = retire.scanFileName("jquery-1.9.0.js", repo);
	assertIsNotVulnerable(test, result);
	test.done();
};
exports.should_not_be_vulnerable_above = function(test) {
	var result = retire.scanFileName("jquery-1.9.1.js", repo);
	assertIsNotVulnerable(test, result);
	test.done();
};
exports.should_be_vulnerable_before = function(test) {
	var result = retire.scanFileName("jquery-1.4.js", repo);
	assertIsVulnerable(test, result);
	test.done();
};
