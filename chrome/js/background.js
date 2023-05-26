/* global chrome, console, exports, CryptoJS, Emitter */

const repoUrl =
  "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";
let updatedAt = Date.now();
let repo;
let repoFuncs;

let vulnerable = {};
const events = new Emitter();
let sandboxWin;

const hasher = {
  sha1: function (data) {
    return CryptoJS.SHA1(data).toString(CryptoJS.enc.Hex);
  },
};

async function download(url) {
  const response = await fetch(url);
  if (response.ok) {
    return response.text();
  } else {
    throw new Error(
      "Got " + response.status + " when trying to download " + url
    );
  }
}

async function downloadRepo() {
  console.log("Downloading repo ...");
  updatedAt = Date.now();
  const repoData = await download(repoUrl + "?" + updatedAt);
  repo = JSON.parse(retire.replaceVersion(repoData));
  console.log("Done");
  vulnerable = {};
  setFuncs();
}

function setFuncs() {
  repoFuncs = {};
  for (var component in repo) {
    if (repo[component].extractors.func) {
      repoFuncs[component] = repo[component].extractors.func;
    }
  }
}

function getFileName(url) {
  var a = document.createElement("a");
  a.href = url;
  return (a.pathname.match(/\/([^\/?#]+)$/i) || [, ""])[1];
}

events.on("scan", function (details) {
  if (details.url.indexOf("chrome-extension://") === 0) return true;

  if (Date.now() - updatedAt > 1000 * 60 * 60 * 6) {
    downloadRepo().then(() => {
      events.emit("scan", details);
    });
    return;
  }
  events.emit("result-ready", details, []);
  console.log("Scanning " + details.url + " ...");
  var results = retire.scanUri(details.url, repo);
  if (results.length > 0) {
    events.emit("result-ready", details, results);
    return;
  }
  results = retire.scanFileName(getFileName(details.url), repo);
  if (results.length > 0) {
    events.emit("result-ready", details, results);
    return;
  }
  download(details.url).then((content) => {
    events.emit("script-downloaded", details, content);
  });
});

events.on("script-downloaded", function (details, content) {
  var results = retire.scanFileContent(content, repo, hasher);
  if (results.length > 0) {
    events.emit("result-ready", details, results);
    return true;
  }
  events.emit("sandbox", details, content);
  console.log(hasher.sha1(content) + " : " + details.url);
  return true;
});

events.on("sandbox", function (details, content) {
  sandboxWin.postMessage(
    {
      tabId: details.tabId,
      script: content,
      url: details.url,
      repoFuncs: repoFuncs,
    },
    "*"
  );
  return true;
});

window.addEventListener("message", function (evt) {
  if (evt.data.version) {
    var results = retire.check(evt.data.component, evt.data.version, repo);
    console.log("SANDBOX", stringifyResults(results));
    events.emit(
      "result-ready",
      { url: evt.data.original.url, tabId: evt.data.original.tabId },
      results
    );
  }
  return true;
});

function stringifyResults(results) {
  return results
    .map((x) => "\n" + x.component + ":" + x.version)
    .reduce((a, b) => a + b, "");
}

events.on("result-ready", function (details, results) {
  var vulnerable = retire.isVulnerable(results);
  if (vulnerable) {
    console.log(details.url, stringifyResults(results));
  }
  if (!vulnerable) console.log(details.url, stringifyResults(results));

  vulnerable[details.url] = results;

  var result = { vulnerable: vulnerable, results: results, url: details.url };
  chrome.runtime.sendMessage({ type: "result", result, details });
});

downloadRepo().then(() => {
  chrome.runtime.sendMessage({ type: "repo-ready" });
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "scan") {
      events.emit("scan", msg.details);
    } else {
      console.log("Background", msg);
    }
  });
});

sandboxWin = window.document.getElementById("sandboxframe").contentWindow;
