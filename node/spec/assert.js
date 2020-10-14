/* global exports, require */

var retire = require("../lib/retire");
var chai = require('chai');
chai.should();

exports.isVulnerable = function(results) {
	retire.isVulnerable(results).should.equal(true);
};

exports.isNotVulnerable = function(results) {
	retire.isVulnerable(results).should.equal(false);
};
