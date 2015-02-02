"use strict";

const retire = require("./retire");
const promise = require("sdk/core/promise");
const Request = require("sdk/request").Request;

const REPO_URL = "https://raw.github.com/RetireJS/retire.js/master/repository/jsrepository.json";

let updatedAt = Date.now();
let repository;
let repoFuncs;
let cache = [];
let vulnerable = {};

exports.getLastUpdated = () => {
  return updatedAt;
}

exports.getRepository = () => {
  return repository;
}

exports.getRepoFuncs = () => {
  return repoFuncs;
}

exports.addToCache = (url) => {
  return cache.push(url);
}

exports.getCache = () => {
  return cache;
}

exports.isCached = (url) => {
  return cache.indexOf(url) > -1;
}

exports.getVulnerable = () => {
  return vulnerable;
}

exports.setVulnerable = (url, info) => {
  return vulnerable[url] = info;
}

exports.download = () => {
  return download();
};

exports.dontCheck = (uri) => {
  return dontCheck(uri);
};

function setFuncs() {
  repoFuncs = {};
  for (let component in repository) {
    if (repository[component].extractors.func) {
      repoFuncs[component] = repository[component].extractors.func;
    }
  }
}

function dontCheck(uri) {
  if (!repository) {
    return false;
  }
  let uris = repository["dont check"].extractors.uri;
  for (let i = 0; i < uris.length; i++) {
    let re = new RegExp(uris[i]);
    if (re.test(uri)) {
      return true;
    }
  }
  return false;
}

// fixme: If download repo fails, log it and show a warning in the button badge.
function download() {
  let deferred = promise.defer();
  console.log("Downloading repo ...");
  updatedAt = Date.now();
  let req = Request({
    url: REPO_URL + "?" + updatedAt,
    onComplete: function (response) {
      repository = JSON.parse(retire.replaceVersion(response.text));
      cache = [];
      vulnerable = {};
      setFuncs();
      deferred.resolve();
      console.log("Repo downloaded");
    }
  }).get();
  return deferred.promise;
}
