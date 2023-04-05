/*jshint esversion: 6 */

var retire = require('../retire');
var fs = require('fs');
var uuidv4 = require('uuid').v4;

function configureCycloneDXJSONLogger(logger, writer, config, hash) {
    var vulnsFound = false;
    var finalResults = { version: retire.version, start: new Date(), data: [], messages: [], errors: [] };
    logger.info = finalResults.messages.push;
    logger.debug = config.verbose ? finalResults.messages.push : function() {};
    logger.warn = logger.error = finalResults.errors.push;
    logger.logVulnerableDependency = function(finding) {
        vulnsFound = true;
        finalResults.data.push(finding);
    };
    logger.logDependency = function(finding) {
        if (finding.results.length > 0) {
          finalResults.data.push(finding); 
        }
    };

    logger.close = function(callback) {
        var write = vulnsFound ? writer.err : writer.out;
        finalResults.start = finalResults.start.toISOString();
        var seen = {};
        var components = finalResults.data.filter(d => d.results).map(r => r.results.map(dep => {
            dep.version = (dep.version.split(".").length >= 3 ? dep.version : dep.version + ".0").replace(/-/g, ".");
            var hashes;
            var filepath = r.file || dep.file;
            if (filepath) {
                var file = fs.readFileSync(filepath);
                hashes = [
                    { "alg" : "MD5", "content" : hash.md5(file) },
                    { "alg" : "SHA-1", "content" : hash.sha1(file) },
                    { "alg" : "SHA-256", "content" : hash.sha256(file) },
                    { "alg" : "SHA-512", "content" : hash.sha512(file) },
                ];
            }
            var purl = `pkg:npm/${dep.component}@${dep.version}`;
            if (seen[purl]) return;
            seen[purl] = true;
            return {
                type: "library",
                name: dep.component,
                version: dep.version,
                purl: purl,
                hashes: hashes
            };
        }).filter(x => x != undefined)).reduce((a,b) => a.concat(b));
        write(JSON.stringify({
            bomFormat    : "CycloneDX",
            specVersion  : "1.4",
            serialNumber : `urn:uuid:${ uuidv4() }`,
            version      : 1,
            metadata     : {
                timestamp : finalResults.start,
                tools     : [
                    {
                        vendor  : "RetireJS",
                        name    : "retire.js",
                        version : retire.version
                    }
                ]
            },
            components   : components
        }, undefined, 2));
        writer.close(callback); 
    };
}

exports.configure = configureCycloneDXJSONLogger;