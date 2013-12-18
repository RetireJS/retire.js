"use strict";

const repo = require("./repo");
const retire = require("./retire");
const hasher = require("./sha1");
const sandbox = require("./sandbox");
const systemEvents = require("sdk/system/events");
const Request = require("sdk/request").Request;
const URL = require("sdk/url").URL;

exports.scan = function(details) {
  return scan(details);
};

exports.getFileName = function(url) {
  return getFileName(url);
}

function scan(details) {
  if ((Date.now() - repo.getLastUpdated()) > 1000*60*60*6) {
    repo.download().then(() => { 
      scan(details); 
    });
    return;
  }
  if (repo.isCached(details.url)) {
    if (repo.getVulnerable().hasOwnProperty(details.url)) {
      onResultReady(details, repo.getVulnerable()[details.url]);
    }
    return;
  }
  repo.addToCache(details.url);
  let results = retire.scanUri(details.url, repo.getRepository());
  if (results.length > 0) {
    console.log("scanUri", results);
    onResultReady(details, results);
    return;
  }
  results = retire.scanFileName(getFileName(details.url), repo.getRepository());
  if (results.length > 0) {
    console.log("scanFileName, result: ", results);
    onResultReady(details, results);
    return;
  }
  let req = Request({
    url: details.url,
    onComplete: function (response) {
      onScriptDownloaded(details, response.text); 
    }
  }).get();
  return;
}

function onScriptDownloaded(details, content) {
  let results = retire.scanFileContent(content, repo.getRepository(), hasher);
  if (results.length > 0) {
    console.log("scanFileContent, result:", results);
    onResultReady(details, results);
    return;
  }
  sandbox.run(content, repo.getRepoFuncs(), details, onVersionDetected);
}

function onVersionDetected(result, details) {
  if (result.version) {
    let results = retire.check(result.component, result.version, repo.getRepository());
    console.log("onVersionDetected", results);
    onResultReady(details, results);
  }
}

function onResultReady(details, results) {
  if (retire.isVulnerable(results)) {
    console.log("vulnerable resultReady: ", details);
    repo.setVulnerable(details.url, results);
    let rmsg = [];
    for (let i in results) {
      rmsg = rmsg.concat(results[i].vulnerabilities);
    }
    systemEvents.emit("retirejs:scanner:on-result-ready", {
      data: "",
      subject: {
        details: details,
        msg: rmsg.join(" ")
      }
    });
  }
}

function getFileName(url) {
  var path = new URL(url).path;
  var filename = (path.match(/[^\/?#]+(?=$|[?#])/) || [""])[0];
  return filename;
}
