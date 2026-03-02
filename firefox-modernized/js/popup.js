/* global browser, console */

document.addEventListener('DOMContentLoaded', initializePopup);

async function initializePopup() {
    try {
        // Get current tab
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        const currentTab = tabs[0];
        
        if (!currentTab) {
            console.error('No active tab found');
            return;
        }
        
        // Get status from background script
        const status = await browser.runtime.sendMessage({ type: "get-status" });
        updateUI(status);
        
        // Get detected vulnerabilities from content script
        try {
            const vulnerabilities = await browser.tabs.sendMessage(currentTab.id, { type: "get-detected" });
            displayVulnerabilities(vulnerabilities || []);
        } catch (error) {
            console.warn('Failed to get vulnerabilities from content script:', error);
            displayVulnerabilities([]);
        }
        
        // Set up event listeners
        setupEventListeners(currentTab.id);
        
    } catch (error) {
        console.error('Failed to initialize popup:', error);
        showError('Failed to load extension data');
    }
}

function updateUI(status) {
    // Update toggle buttons
    const scanToggle = document.getElementById('toggle-scan');
    const deepScanToggle = document.getElementById('toggle-deep-scan');
    
    updateToggleButton(scanToggle, status.scanEnabled);
    updateToggleButton(deepScanToggle, status.deepScanEnabled);
    
    // Update vulnerability count
    const countElement = document.getElementById('vulnerability-count');
    const count = status.vulnerabilityCount || 0;
    countElement.textContent = count;
    countElement.className = `vulnerability-badge ${count === 0 ? 'zero' : ''}`;
}

function updateToggleButton(button, enabled) {
    const textElement = button.querySelector('.toggle-text');
    if (enabled) {
        button.classList.remove('disabled');
        textElement.textContent = 'Enabled';
    } else {
        button.classList.add('disabled');
        textElement.textContent = 'Disabled';
    }
}

function displayVulnerabilities(vulnerabilities) {
    const listElement = document.getElementById('vulnerability-list');
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
        listElement.innerHTML = `
            <div class="no-vulnerabilities">
                <span class="checkmark">✓</span>
                <p>No known vulnerable libraries detected</p>
            </div>
        `;
        return;
    }
    
    // Group vulnerabilities by component
    const grouped = groupVulnerabilities(vulnerabilities);
    
    listElement.innerHTML = Object.entries(grouped)
        .map(([component, vulns]) => createVulnerabilityItem(component, vulns))
        .join('');
}

function groupVulnerabilities(vulnerabilities) {
    const grouped = {};
    
    vulnerabilities.forEach(vuln => {
        const key = `${vuln.component}-${vuln.version}`;
        if (!grouped[key]) {
            grouped[key] = {
                component: vuln.component,
                version: vuln.version,
                detection: vuln.detection,
                vulnerabilities: []
            };
        }
        
        if (vuln.vulnerabilities) {
            grouped[key].vulnerabilities.push(...vuln.vulnerabilities);
        }
    });
    
    return grouped;
}

function createVulnerabilityItem(key, vulnData) {
    const { component, version, detection, vulnerabilities } = vulnData;
    
    const severityBadges = vulnerabilities
        .map(v => {
            const severity = (v.severity || 'unknown').toLowerCase();
            return `<span class="severity-badge severity-${severity}">${severity}</span>`;
        })
        .join('');
    
    const details = vulnerabilities
        .map(v => v.info || [])
        .flat()
        .filter((info, index, arr) => arr.indexOf(info) === index) // Remove duplicates
        .join(', ');
    
    return `
        <div class="vulnerability-item">
            <div class="vulnerability-component">${component}</div>
            <div class="vulnerability-version">Version ${version} (${detection})</div>
            <div class="vulnerability-details">
                ${severityBadges}
                <div>${details}</div>
            </div>
        </div>
    `;
}

function setupEventListeners(tabId) {
    // Toggle scan button
    document.getElementById('toggle-scan').addEventListener('click', async () => {
        try {
            const response = await browser.runtime.sendMessage({ type: "toggle-scan" });
            const button = document.getElementById('toggle-scan');
            updateToggleButton(button, response.scanEnabled);
        } catch (error) {
            console.error('Failed to toggle scan:', error);
        }
    });
    
    // Toggle deep scan button
    document.getElementById('toggle-deep-scan').addEventListener('click', async () => {
        try {
            const response = await browser.runtime.sendMessage({ type: "toggle-deep-scan" });
            const button = document.getElementById('toggle-deep-scan');
            updateToggleButton(button, response.deepScanEnabled);
        } catch (error) {
            console.error('Failed to toggle deep scan:', error);
        }
    });
    
    // Rescan button
    document.getElementById('rescan-btn').addEventListener('click', async () => {
        const button = document.getElementById('rescan-btn');
        button.disabled = true;
        button.innerHTML = '<span>Rescanning...</span>';
        
        try {
            // Reload the tab to trigger a fresh scan
            await browser.tabs.reload(tabId);
            
            // Close popup after initiating rescan
            setTimeout(() => {
                window.close();
            }, 500);
            
        } catch (error) {
            console.error('Failed to rescan:', error);
            button.disabled = false;
            button.innerHTML = '<span>Rescan Page</span>';
        }
    });
    
    // Report button
    document.getElementById('report-btn').addEventListener('click', () => {
        // Open detailed report in new tab
        browser.tabs.create({
            url: browser.runtime.getURL('html/report.html')
        });
    });
    
    // Settings link
    document.getElementById('settings-link').addEventListener('click', (e) => {
        e.preventDefault();
        browser.tabs.create({
            url: browser.runtime.getURL('html/settings.html')
        });
    });
    
    // Help link
    document.getElementById('help-link').addEventListener('click', (e) => {
        e.preventDefault();
        browser.tabs.create({
            url: 'https://github.com/RetireJS/retire.js/wiki'
        });
    });
}

function showError(message) {
    const container = document.querySelector('.popup-container');
    container.innerHTML = `
        <div class="header">
            <img src="../icons/icon48.png" alt="retire.js" class="logo">
            <h1>retire.js</h1>
        </div>
        <div class="error-message">
            <p>${message}</p>
        </div>
    `;
}