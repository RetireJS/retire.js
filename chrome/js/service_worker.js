var scanEnabled = true;

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

chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
  console.log("worker", msg);
  if (msg.type == "repo-ready") {
    chrome.webNavigation.onBeforeNavigate.addListener(() => {
      if (listening) return;
      listening = true;
      chrome.webRequest.onCompleted.addListener(
        (details) => {
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
  } else if (msg.message == "enabled") {
    scanEnabled = msg.data;
  } else if (msg.type == "ping") {
    //ignore
  } else {
    console.warn("worker", msg);
  }
});

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
