#!/usr/bin/env node
const crypto = require("crypto");
const testCases = require("./testcases.json");

const retire = require("../node/lib/retire.js");
const repo = require("../node/lib/repo.js");
const reporting = require("../node/lib/reporting.js")
const options = {
    log : reporting.open({})
}

const limit = process.argv[2];

var hash = {
    'sha1' : function(data) {
      shasum   = crypto.createHash('sha1');
      shasum.update(data);
      return shasum.digest('hex');
    }
};

const https = require("https");
const dlCache = {};
async function dl(uri) {
    console.log(`  Downloading ${uri}`);
    return new Promise((resolve, reject) => {
        if (dlCache[uri]) return resolve(dlCache[uri]);
        let d = https.get(uri, (res) => {
            if (res.statusCode != 200) {
                return reject("Failed to download " + uri + ": " + res.statusCode);                    
            }
            let d = [];
            res.on("data", data => d.push(data));
            res.on("end", () => { 
                dlCache[uri] = Buffer.concat(d);
                resolve(dlCache[uri]);
            });
        });
        d.on("error", (err) => {
            console.warn(err);
            return reject("Failed to download " + uri);
        })
    });
}

function exitWithError(...msg) {
	console.warn(...msg);
	process.exit(1);
}

async function runTests(jsRepo) {
    for (let [name, content] of Object.entries(testCases)) {
        if (limit && limit != name) continue;
        console.log(`Testing ${name}`)
        for (let [template, tcontent] of Object.entries(content)) {
            let { versions, subversions, contentOnly } = tcontent;
            subversions = subversions || [ "" ];
            for (let version of versions) {
                for (let sub of subversions) {
                    let t = template.replace("§§version§§", version).replace("§§subversion§§", sub);
                    if (!contentOnly) {
                        let resultsUri = retire.scanUri(t, jsRepo);
                        let resultsFilename = retire.scanFileName(t.split("/").pop(), jsRepo);
                        let results = resultsUri.concat(resultsFilename);
                        if (results.length == 0) {
                            exitWithError(`Did not detect ${version} of ${name} using uri or filename on ${t}` )
                        }
                        if (results.length > 1) {
                            exitWithError(`Detect multiple components in ${name} using uri and filename on ${t} : ${results.map(a => a.component).join(", ")}` )
                        }
                        if (results[0].component != name) {
                            exitWithError(`Wrong component for ${version} of ${name} using uri or filename on ${t}: ${results[0].component}` )
                        }
                        if (!results[0].version.startsWith(version)) {
                            exitWithError(`Wrong version for ${version} of ${name} using uri or filename on ${t}: ${results[0].version}` )
                        }
                    }
                    let content = await dl(t);
                    let contentResults = retire.scanFileContent(content, jsRepo, hash);
                    if (contentResults.length == 0) {
                        exitWithError(`Did not detect ${version} of ${name} using content on ${t}` )
                    }
                    if (contentResults.length > 1 && contentResults[0].component != "jquery-ui") { //Allow multiple detections for jquery ui due to dialog, autocomplete etc.
                        exitWithError(`Detect multiple components in ${name} using content on ${t} : ${contentResults.map(a => a.component).join(", ")}` )
                    }
                    if (contentResults[0].component != name) {
                        exitWithError(`Wrong component for ${version} of ${name} using uri or filename on ${t}: ${contentResults[0].component}` )
                    }
                    if (!contentResults[0].version.startsWith(version)) {
                        exitWithError(`Wrong version for ${version} of ${name} using content on ${t}: ${contentResults[0].version}` )
                    }
                    console.log(`  - ${contentResults[0].component} @ ${contentResults[0].version}`)
                }
            }
        }
        console.log(" Successfully tested uri/filename and content detection!")
    }

}


repo.loadrepositoryFromFile("./jsrepository.json", options).on('done', (jsRepo) =>  {
    runTests(jsRepo)
        .then(() => console.log("Done!"))
        .catch(err => console.warn("Failed!", err));
})
