#!/usr/bin/env node

const crypto = require("crypto");
const testCases = require("./testcases.json");

const retire = require("../node/lib/retire.js");
const repo = require("../node/lib/repo.js");
const reporting = require("../node/lib/reporting.js");
const options = {
  log: reporting.open({}),
};

const limit = process.argv[2];

var hash = {
  sha1: function (data) {
    shasum = crypto.createHash("sha1");
    shasum.update(data);
    return shasum.digest("hex");
  },
};

const https = require("https");
const dlCache = {};
async function dl(uri) {
  console.log(`  Downloading ${uri}`);
  return new Promise((resolve, reject) => {
    if (dlCache[uri]) return resolve(dlCache[uri]);
    let d = https.get(uri, (res) => {
      let d = [];
      res.on("data", (data) => d.push(data));
      res.on("end", () => {
        if (res.statusCode != 200) {
          return reject("Failed to download " + uri + ": " + res.statusCode);
        }
        dlCache[uri] = Buffer.concat(d);
        resolve(dlCache[uri]);
      });
    });
    d.on("error", (err) => {
      failure(err);
      return reject("Failed to download " + uri);
    });
  });
}

function exitWithError(...msg) {
  failure(...msg);
  process.exit(1);
}
const colors = {
  Reset: "\x1b[0m",
  Green: "\x1b[32m",
  Red: "\x1b[31m",
};

function success(...msg) {
  console.log(colors.Green, ...msg, colors.Reset);
}
function failure(...msg) {
  console.warn(colors.Red, ...msg, colors.Reset);
}

async function runTests(jsRepo) {
  for (let [name, content] of Object.entries(testCases)) {
    if (limit && limit != name) continue;
    console.log(`Testing ${name}`);
    for (let [template, tcontent] of Object.entries(content)) {
      let {
        versions,
        subversions,
        contentOnly,
        additionalVersions,
        allowedOtherComponents,
      } = tcontent;
      if (limit) {
        versions = Array.from(
          new Set(versions.concat(additionalVersions || []))
        );
      }
      subversions = subversions || [""];
      for (let version of versions) {
        for (let sub of subversions) {
          let t = template
            .replace(/§§version§§/g, version)
            .replace(/§§subversion§§/g, sub);
          if (!contentOnly) {
            let resultsUri = retire.scanUri(t, jsRepo);
            let resultsFilename = retire.scanFileName(
              t.split("/").pop(),
              jsRepo
            );
            let results = resultsUri.concat(resultsFilename);
            if (results.length == 0) {
              exitWithError(
                `Did not detect ${version} of ${name} using uri or filename on ${t}`
              );
            }
            if (results.length > 1) {
              exitWithError(
                `Detect multiple components in ${name} using uri and filename on ${t} : ${results
                  .map((a) => a.component)
                  .join(", ")}`
              );
            }
            if (results[0].component != name) {
              exitWithError(
                `Wrong component for ${version} of ${name} using uri or filename on ${t}: ${results[0].component}`
              );
            }
            if (!results[0].version.startsWith(version)) {
              exitWithError(
                `Wrong version for ${version} of ${name} using uri or filename on ${t}: ${results[0].version}`
              );
            }
          }
          let content = "";
          try {
            content = await dl(t);
          } catch (e) {
            if (e.message.includes("Failed to download")) {
              console.log("Failed to download, ignoring");
              continue;
            }
            if (sub == ".min") {
              console.log("Ignoring missing minified version", e);
              continue;
            }
            exitWithError(`Failed to download ${t}: ${e}`);
          }
          let contentResults = retire.scanFileContent(content, jsRepo, hash);
          if (allowedOtherComponents)
            contentResults = contentResults.filter(
              (x) => !allowedOtherComponents.includes(x.component)
            );
          if (contentResults.length == 0) {
            exitWithError(
              `Did not detect ${version} of ${name} using content on ${t}`
            );
          }
          if (
            contentResults.length > 1 &&
            contentResults[0].component != "jquery-ui"
          ) {
            //Allow multiple detections for jquery ui due to dialog, autocomplete etc.
            exitWithError(
              `Detect multiple components in ${name} using content on ${t} : ${contentResults
                .map((a) => a.component)
                .join(", ")}`
            );
          }
          if (contentResults[0].component != name) {
            exitWithError(
              `Wrong component for ${version} of ${name} using uri or filename on ${t}: ${contentResults[0].component}`
            );
          }
          if (!contentResults[0].version.startsWith(version)) {
            exitWithError(
              `Wrong version for ${version} of ${name} using content on ${t}: ${contentResults[0].version}`
            );
          }
          success(
            `  - ${contentResults[0].component} @ ${contentResults[0].version}`
          );
        }
      }
    }
    success(" Successfully tested uri/filename and content detection!");
  }
}

repo
  .loadrepositoryFromFile("./jsrepository.json", options)
  .then((jsRepo) => runTests(jsRepo))
  .then(() => console.log("Done!"))
  .catch((err) => console.warn("Failed!", err));
