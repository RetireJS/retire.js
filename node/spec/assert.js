/* global exports, require */

var retire = require("../lib/retire");

exports.isVulnerable = function(test, results) {
	test.equal(true, retire.isVulnerable(results));
};

exports.isNotVulnerable = function(test, results) {
	test.equal(false, retire.isVulnerable(results));
};
