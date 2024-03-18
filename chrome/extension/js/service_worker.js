import "./generated/retire-chrome.js";

const retire = retirechrome.retire;
console.log(retire);

var scanEnabled = true;
var deepScanEnabled = true;
var repo;

async function createOffscreen() {
  if (await chrome.offscreen.hasDocument()) return;
  chrome.offscreen.createDocument({
    url: chrome.runtime.getURL("background.html"),
    reasons: ["IFRAME_SCRIPTING"],
    justification: "Download and investigate scripts to detect versions",
  });
}
createOffscreen();

chrome.action.setBadgeBackgroundColor({ color: [255, 0, 0, 255] });

let listening = false;

function messageHandler(msg, sendResponse) {
  if (msg.type == "repo-ready") {
    repo = msg.repo;
    chrome.webNavigation.onBeforeNavigate.addListener(() => {
      if (listening) return;
      listening = true;
      chrome.webRequest.onCompleted.addListener(
        (details) => {
          //console.log("Completed", details.url, details.type);
          if (details.type == "script") {
            chrome.runtime.sendMessage({
              type: "scan",
              details,
              offscreen: true,
            });
          }
        },
        { urls: ["<all_urls>"] }
      );
    });
  } else if (msg.type == "result") {
    showResult(msg.result, msg.details);
  } else if (msg.message == "enabled?") {
    sendResponse({ enabled: scanEnabled });
  } else if (msg.message == "enable") {
    scanEnabled = !scanEnabled;
  } else if (msg.message == "deepScanEnabled?") {
    sendResponse({ enabled: deepScanEnabled });
  } else if (msg.message == "deepScanEnable") {
    deepScanEnabled = !deepScanEnabled;
  } else if (msg.type == "astScan") {
    if (!deepScanEnabled) return;
    const content = msg.content;
    const ds = Date.now();
    const results = astScan(content, repo, msg.url);
    console.log(
      "Scanning from the service worker: ",
      results,
      content.length,
      Date.now() - ds,
      msg.url
    );
    sendResponse({ results });
  } else if (msg.type == "ping") {
    //ignore
  } else {
    console.warn("worker", msg);
  }
}

chrome.runtime.onConnect.addListener((port) => {
  console.assert(port.name == "background");
  console.log("Port established", port.name);
  port.onMessage.addListener((msg) => {
    console.log("Worker received port message", msg);
  });
});

chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
  console.log("Worker received message of type", msg.type);
  messageHandler(msg, sendResponse);
});

function unique(a) {
  return a.reduce(function (p, c) {
    if (!p.some((x) => x[0] == c[0] && x[1] == c[1])) p.push(c);
    return p;
  }, []);
}

const seenAST = new Map();

function buf2hex(buffer) {
  // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function astScan(content, repo, url) {
  if (seenAST.has(url)) {
    console.log("Returning cached for AST scan", url, seenAST.get(url));
    return seenAST.get(url);
  }

  const results = unique(retirechrome.deepScan(content, repo));
  console.log("Direct AST results", results);
  const prepared = results
    .map(({ component, version }) => retire.check(component, version, repo))
    .reduce((a, b) => a.concat(b), [])
    .map((x) => {
      x.detection = "ast";
      return x;
    });
  seenAST.set(url, prepared);
  return prepared;
}

function showResult(result, details) {
  //setTimeout(function () {
  if (result.vulnerable) {
    chrome.action.setBadgeTextColor({ color: "#fff", tabId: details.tabId });
    chrome.action.setBadgeText({ text: "!", tabId: details.tabId });
  }
  if (details.tabId >= 0) {
    console.log(details.tabId, result);
    chrome.tabs.sendMessage(
      details.tabId,
      {
        message: JSON.stringify(result),
      },
      function (response) {
        let e = chrome.runtime.lastError;
        if (e) {
          chrome.runtime.lastError = undefined;
          console.warn("Failed to send message:", e, details);
        }
        console.log(details.tabId, response);
        if (response && response.count > 0) {
          chrome.action.setBadgeText({
            text: "" + response.count,
            tabId: details.tabId,
          });
        }
        return false;
      }
    );
  }
  return true;
  //}, 3000);
}
