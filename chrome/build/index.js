const deepScan = require("../../node/lib/deepscan.js").deepScan;
const retire = require("../../node/lib/retire.js");
const sha1 = require('hash.js/lib/hash/sha/1');
exports.repo = require("../../repository/jsrepository-v5-combined.json");
exports.retire = retire;
exports.sha1 = sha1;
exports.deepScan = deepScan;
