/* global chrome, console, exports, CryptoJS, Emitter */

const repoUrl =
  "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v3.json";
let updatedAt = Date.now();
let repo;
let backdoorData;
let repoFuncs;

const retire = retirechrome.retire;

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
  let repoData = JSON.stringify(retirechrome.repo);
  try {
    const dlRepo = await download(repoUrl + "?" + updatedAt);
    repoData = dlRepo;
  } catch (e) {
    console.error(
      "Failed to download repo from " + repoUrl + " - Using local data",
      e
    );
  }
  const parsedRepo = JSON.parse(retire.replaceVersion(repoData));
  repo = parsedRepo.advisories;
  backdoorData = parsedRepo.backdoored;
  console.log(repo);
  console.log(backdoorData);
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

function scanUrlBackdoored(url) {
  console.log("Scanning url for bd: ", url);
  const matches = Object.entries(backdoorData).filter(([title, advisories]) => {
    return advisories.some((advisory) => {
      return advisory.extractors.some((e) => {
        return new RegExp(e).test(url);
      });
    });
  });
  const remapped = matches.map(([title, advisories]) => {
    return {
      component: title,
      version: "-",
      detection: "url",
      vulnerabilities: advisories.map((a) => {
        return {
          ...a,
          identifiers: {
            summary: a.summary,
          },
        };
      }),
    };
  });
  console.log("BD matches", remapped);
  return remapped;
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
  var bd = scanUrlBackdoored(details.url);
  if (bd.length > 0) {
    events.emit("result-ready", details, bd);
    return;
  }
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
    if (content.startsWith("/*! For license information please see ")) {
      const licenseFilename = content
        .split("/*! For license information please see ")[1]
        .split(" */")[0];
      const licenseUrl =
        details.url
          .split("?")[0]
          .split("#")[0]
          .split("/")
          .slice(0, -1)
          .join("/") +
        "/" +
        licenseFilename;
      download(licenseUrl).then((licenseContent) => {
        events.emit("script-downloaded", details, licenseContent);
      });
    }
  });
});

function unique(a) {
  return a.reduce(function (p, c) {
    if (!p.some((x) => x[0] == c[0] && x[1] == c[1])) p.push(c);
    return p;
  }, []);
}

function astScan(content, details, contentResults) {
  chrome.runtime.sendMessage(
    {
      type: "astScan",
      url: details.url,
      content,
    },
    (response) => {
      if (!response) {
        console.warn("No response", chrome.runtime.lastError);
        return;
      }
      console.log("A response was received", response.data);
      const astResults = response.results;
      console.log("Results from the service worker", astResults);
      var results = astResults.filter((x) => {
        return !contentResults.some(
          (b) => x.component == b.component && x.version == b.version
        );
      });
      console.log("Results from the service worker after filtering", results);
      if (results.length > 0) {
        events.emit("result-ready", details, results);
      }
    }
  );
}

events.on("script-downloaded", function (details, content) {
  console.log("Scanning content of " + details.url + " ...");
  const bs = Date.now();
  var results = retire.scanFileContent(content, repo, hasher);
  astScan(content, details, results);
  if (results.length > 0) {
    events.emit("result-ready", details, results);
    return true;
  }
  events.emit("sandbox", details, content);
  console.log(hasher.sha1(content) + " : " + details.url);
  return true;
});

events.on("sandbox", function (details, content) {
  console.log("Sending to the sandbox");
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

setInterval(() => {
  chrome.runtime.sendMessage({ type: "ping" });
}, 5000);

downloadRepo().then(() => {
  chrome.runtime.sendMessage({ type: "repo-ready", repo: repo });
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "scan") {
      events.emit("scan", msg.details);
    } else {
      console.log("Background", msg);
    }
    return false;
  });
});

sandboxWin = window.document.getElementById("sandboxframe").contentWindow;
