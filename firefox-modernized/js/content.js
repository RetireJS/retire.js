/* global browser, console */

let vulnerabilityCount = 0;
const detectedVulnerabilities = [];

// Listen for messages from background script
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "vulnerability-found":
      handleVulnerabilityFound(message);
      break;
    case "scan-result":
      handleScanResult(message);
      break;
    case "get-detected":
      sendResponse(detectedVulnerabilities);
      break;
    default:
      console.warn("Unknown message type in content script:", message.type);
  }
});

function handleVulnerabilityFound(message) {
  vulnerabilityCount += message.results.length;
  detectedVulnerabilities.push(...message.results);
  
  // Log to console with detailed information
  message.results.forEach(result => {
    if (result.vulnerabilities && result.vulnerabilities.length > 0) {
      const vulnInfo = result.vulnerabilities.map(vuln => {
        const info = vuln.info || [];
        const severity = vuln.severity || 'unknown';
        return `${severity.toUpperCase()}: ${info.join(', ')}`;
      }).join(' | ');
      
      console.warn(
        `⚠️ retire.js: Vulnerable library detected in ${message.url}`,
        `\n📦 Component: ${result.component} ${result.version}`,
        `\n🔍 Detection: ${result.detection || 'unknown'}`,
        `\n🚨 Vulnerabilities: ${vulnInfo}`,
        result
      );
    }
  });
}

function handleScanResult(message) {
  if (message.results && message.results.length > 0) {
    handleVulnerabilityFound({
      url: window.location.href,
      results: message.results
    });
  }
}

// Scan inline scripts for vulnerabilities
function scanInlineScripts() {
  const scripts = document.querySelectorAll('script:not([src])');
  
  scripts.forEach((script, index) => {
    if (script.textContent && script.textContent.trim().length > 100) {
      // Only scan substantial inline scripts
      browser.runtime.sendMessage({
        type: "scan-request",
        content: script.textContent,
        url: `${window.location.href}#inline-${index}`
      });
    }
  });
}

// Scan dynamically loaded scripts
const originalAppendChild = Element.prototype.appendChild;
Element.prototype.appendChild = function(child) {
  const result = originalAppendChild.call(this, child);
  
  if (child.tagName === 'SCRIPT' && child.src) {
    // Let background script handle external scripts via webRequest
    console.log("New script element added:", child.src);
  } else if (child.tagName === 'SCRIPT' && child.textContent) {
    // Scan inline scripts
    browser.runtime.sendMessage({
      type: "scan-request",
      content: child.textContent,
      url: `${window.location.href}#dynamic-inline`
    });
  }
  
  return result;
};

// Initialize scanning when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(scanInlineScripts, 1000); // Wait for scripts to load
  });
} else {
  setTimeout(scanInlineScripts, 1000);
}

// Also scan when new content is added
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        const scripts = node.querySelectorAll ? node.querySelectorAll('script:not([src])') : [];
        scripts.forEach((script, index) => {
          if (script.textContent && script.textContent.trim().length > 100) {
            browser.runtime.sendMessage({
              type: "scan-request",
              content: script.textContent,
              url: `${window.location.href}#mutation-${index}`
            });
          }
        });
      }
    });
  });
});

observer.observe(document.body || document.documentElement, {
  childList: true,
  subtree: true
});

console.log("retire.js Firefox content script loaded");