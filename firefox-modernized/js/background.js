/* global browser, console, retirechrome, RepositoryUpdater */

const retire = retirechrome.retire;
let repo = retirechrome.repo; // Will be updated by RepositoryUpdater

var scanEnabled = true;
var deepScanEnabled = true;
var vulnerabilityCounts = new Map();
var repositoryUpdater = null;

// Initialize repository updater
function initializeRepositoryUpdater() {
    // Load repository updater script first
    const script = document.createElement('script');
    script.src = 'js/repository-updater.js';
    script.onload = () => {
        repositoryUpdater = new RepositoryUpdater();
    };
    document.head.appendChild(script);
}

// Initialize badge color
browser.browserAction.setBadgeBackgroundColor({ color: "#C13832" });

// Listen for web requests to scan JavaScript files
browser.webRequest.onCompleted.addListener(
  (details) => {
    if (!scanEnabled) return;
    
    // Only scan script resources
    if (details.type === "script" && details.statusCode === 200) {
      console.log("Scanning script:", details.url);
      scanScript(details);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Listen for navigation events to reset tab state
browser.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) { // Main frame only
    resetTabState(details.tabId);
  }
});

// Message handler for communication with content scripts and popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "scan-request":
      handleScanRequest(message, sender);
      break;
    case "get-status":
      sendResponse({
        scanEnabled: scanEnabled,
        deepScanEnabled: deepScanEnabled,
        vulnerabilityCount: vulnerabilityCounts.get(sender.tab?.id) || 0
      });
      break;
    case "toggle-scan":
      scanEnabled = !scanEnabled;
      sendResponse({ scanEnabled: scanEnabled });
      break;
    case "toggle-deep-scan":
      deepScanEnabled = !deepScanEnabled;
      sendResponse({ deepScanEnabled: deepScanEnabled });
      break;
    case "ast-scan":
      if (deepScanEnabled) {
        const results = performASTScan(message.content, message.url);
        sendResponse({ results: results });
      } else {
        sendResponse({ results: [] });
      }
      break;
    case "repository-updated":
      // Update local repository reference
      repo = message.repository;
      console.log("Repository updated in background script");
      break;
    case "get-repository-stats":
      if (repositoryUpdater) {
        sendResponse(repositoryUpdater.getStats());
      } else {
        sendResponse(null);
      }
      break;
    case "force-repository-update":
      if (repositoryUpdater) {
        repositoryUpdater.forceUpdate().then(updatedRepo => {
          repo = updatedRepo;
          sendResponse({ success: true });
        }).catch(error => {
          sendResponse({ success: false, error: error.message });
        });
      } else {
        sendResponse({ success: false, error: "Repository updater not initialized" });
      }
      break;
    default:
      console.warn("Unknown message type:", message.type);
  }
});

function scanScript(details) {
  // First try URL-based scanning
  const urlResults = retire.scanUri(details.url, repo);
  if (urlResults.length > 0) {
    console.log("URL-based vulnerabilities found:", urlResults);
    reportVulnerabilities(urlResults, details);
    return;
  }
  
  // Try filename-based scanning
  const filename = getFileName(details.url);
  const filenameResults = retire.scanFileName(filename, repo);
  if (filenameResults.length > 0) {
    console.log("Filename-based vulnerabilities found:", filenameResults);
    reportVulnerabilities(filenameResults, details);
    return;
  }
  
  // For content-based scanning, we need to fetch the script
  if (deepScanEnabled) {
    fetch(details.url)
      .then(response => response.text())
      .then(content => {
        const contentResults = performContentScan(content, details.url);
        if (contentResults.length > 0) {
          console.log("Content-based vulnerabilities found:", contentResults);
          reportVulnerabilities(contentResults, details);
        }
      })
      .catch(error => {
        console.warn("Failed to fetch script for content scanning:", error);
      });
  }
}

function performContentScan(content, url) {
  const results = [];
  
  // Hash-based scanning
  const hashResults = retire.scanFileContent(content, repo, { 
    url: url,
    hash: retire.sha1(content)
  });
  results.push(...hashResults);
  
  // AST-based deep scanning
  if (deepScanEnabled) {
    const astResults = performASTScan(content, url);
    results.push(...astResults);
  }
  
  return results;
}

function performASTScan(content, url) {
  try {
    const results = retirechrome.deepScan(content, repo);
    return results.map(result => {
      const vulnerabilities = retire.check(result.component, result.version, repo);
      return {
        ...result,
        vulnerabilities: vulnerabilities,
        detection: 'ast'
      };
    });
  } catch (error) {
    console.warn("AST scanning failed:", error);
    return [];
  }
}

function reportVulnerabilities(results, details) {
  const vulnerableResults = results.filter(r => r.vulnerabilities && r.vulnerabilities.length > 0);
  
  if (vulnerableResults.length === 0) return;
  
  // Update vulnerability count for tab
  const tabId = details.tabId;
  const currentCount = vulnerabilityCounts.get(tabId) || 0;
  const newCount = currentCount + vulnerableResults.length;
  vulnerabilityCounts.set(tabId, newCount);
  
  // Update badge
  updateBadge(tabId, newCount);
  
  // Send to content script for console logging
  browser.tabs.sendMessage(tabId, {
    type: "vulnerability-found",
    url: details.url,
    results: vulnerableResults
  }).catch(error => {
    console.warn("Failed to send message to content script:", error);
  });
}

function updateBadge(tabId, count) {
  if (count > 0) {
    browser.browserAction.setBadgeText({ 
      text: count.toString(), 
      tabId: tabId 
    });
    browser.browserAction.setBadgeTextColor({ 
      color: "#ffffff", 
      tabId: tabId 
    });
  } else {
    browser.browserAction.setBadgeText({ 
      text: "", 
      tabId: tabId 
    });
  }
}

function resetTabState(tabId) {
  vulnerabilityCounts.delete(tabId);
  updateBadge(tabId, 0);
}

function getFileName(url) {
  try {
    const urlObj = new URL(url);
    const pathname = urlObj.pathname;
    return pathname.split('/').pop() || '';
  } catch (error) {
    console.warn("Failed to parse URL:", url, error);
    return '';
  }
}

function handleScanRequest(message, sender) {
  // Handle requests from content scripts for additional scanning
  if (message.content) {
    const results = performContentScan(message.content, message.url || sender.url);
    browser.tabs.sendMessage(sender.tab.id, {
      type: "scan-result",
      results: results
    });
  }
}

// Clean up tab data when tabs are closed
browser.tabs.onRemoved.addListener((tabId) => {
  vulnerabilityCounts.delete(tabId);
});

console.log("retire.js Firefox extension background script loaded");

// Initialize repository updater
initializeRepositoryUpdater();