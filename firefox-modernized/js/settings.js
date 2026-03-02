/* global browser, console */

// Default settings
const DEFAULT_SETTINGS = {
    enableScanning: true,
    enableDeepScan: true,
    enableConsoleLogging: true,
    updateFrequency: 6, // hours
    scanTimeout: 10, // seconds
    maxFileSize: 5, // MB
    respectDnt: false,
    localStorageOnly: true,
    debugMode: false
};

// Settings storage key
const SETTINGS_KEY = 'retirejs_settings';

// Initialize settings page
document.addEventListener('DOMContentLoaded', initializeSettings);

async function initializeSettings() {
    try {
        // Load current settings
        const settings = await loadSettings();
        
        // Populate form with current settings
        populateForm(settings);
        
        // Load repository statistics
        await loadRepositoryStats();
        
        // Set up event listeners
        setupEventListeners();
        
        console.log('Settings page initialized');
        
    } catch (error) {
        console.error('Failed to initialize settings:', error);
        showSaveStatus('Failed to load settings', true);
    }
}

async function loadSettings() {
    try {
        const stored = await browser.storage.local.get(SETTINGS_KEY);
        return { ...DEFAULT_SETTINGS, ...stored[SETTINGS_KEY] };
    } catch (error) {
        console.error('Failed to load settings:', error);
        return DEFAULT_SETTINGS;
    }
}

async function saveSettings(settings) {
    try {
        await browser.storage.local.set({ [SETTINGS_KEY]: settings });
        showSaveStatus('Settings saved successfully');
        return true;
    } catch (error) {
        console.error('Failed to save settings:', error);
        showSaveStatus('Failed to save settings', true);
        return false;
    }
}

function populateForm(settings) {
    // Checkboxes
    document.getElementById('enable-scanning').checked = settings.enableScanning;
    document.getElementById('enable-deep-scan').checked = settings.enableDeepScan;
    document.getElementById('enable-console-logging').checked = settings.enableConsoleLogging;
    document.getElementById('respect-dnt').checked = settings.respectDnt;
    document.getElementById('local-storage-only').checked = settings.localStorageOnly;
    document.getElementById('debug-mode').checked = settings.debugMode;
    
    // Select boxes
    document.getElementById('update-frequency').value = settings.updateFrequency;
    document.getElementById('scan-timeout').value = settings.scanTimeout;
    document.getElementById('max-file-size').value = settings.maxFileSize;
}

function collectFormData() {
    return {
        enableScanning: document.getElementById('enable-scanning').checked,
        enableDeepScan: document.getElementById('enable-deep-scan').checked,
        enableConsoleLogging: document.getElementById('enable-console-logging').checked,
        updateFrequency: parseInt(document.getElementById('update-frequency').value),
        scanTimeout: parseInt(document.getElementById('scan-timeout').value),
        maxFileSize: parseInt(document.getElementById('max-file-size').value),
        respectDnt: document.getElementById('respect-dnt').checked,
        localStorageOnly: document.getElementById('local-storage-only').checked,
        debugMode: document.getElementById('debug-mode').checked
    };
}

async function loadRepositoryStats() {
    const statsElement = document.getElementById('repository-stats');
    
    try {
        const stats = await browser.runtime.sendMessage({ type: 'get-repository-stats' });
        
        if (stats) {
            const lastUpdate = stats.lastUpdate ? new Date(stats.lastUpdate).toLocaleString() : 'Never';
            
            statsElement.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-value">${stats.libraries}</span>
                        <span class="stat-label">Libraries</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">${stats.vulnerabilities}</span>
                        <span class="stat-label">Vulnerabilities</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">${stats.extractors}</span>
                        <span class="stat-label">Extractors</span>
                    </div>
                </div>
                <div class="last-update">Last updated: ${lastUpdate}</div>
            `;
        } else {
            statsElement.innerHTML = '<div class="stat-loading">Repository statistics unavailable</div>';
        }
        
    } catch (error) {
        console.error('Failed to load repository stats:', error);
        statsElement.innerHTML = '<div class="stat-loading">Failed to load statistics</div>';
    }
}

function setupEventListeners() {
    // Auto-save on form changes
    const inputs = document.querySelectorAll('input, select');
    inputs.forEach(input => {
        input.addEventListener('change', debounce(autoSave, 1000));
    });
    
    // Update repository button
    document.getElementById('update-repository').addEventListener('click', updateRepository);
    
    // Reset settings button
    document.getElementById('reset-settings').addEventListener('click', resetSettings);
}

async function autoSave() {
    const settings = collectFormData();
    await saveSettings(settings);
}

async function updateRepository() {
    const button = document.getElementById('update-repository');
    const originalText = button.textContent;
    
    button.disabled = true;
    button.innerHTML = '<span class="loading-spinner"></span>Updating...';
    
    try {
        const response = await browser.runtime.sendMessage({ type: 'force-repository-update' });
        
        if (response.success) {
            showSaveStatus('Repository updated successfully');
            await loadRepositoryStats(); // Refresh stats
        } else {
            showSaveStatus(`Update failed: ${response.error}`, true);
        }
        
    } catch (error) {
        console.error('Failed to update repository:', error);
        showSaveStatus('Update failed: Network error', true);
    } finally {
        button.disabled = false;
        button.textContent = originalText;
    }
}

async function resetSettings() {
    if (!confirm('Are you sure you want to reset all settings to their defaults? This action cannot be undone.')) {
        return;
    }
    
    try {
        // Reset to defaults
        populateForm(DEFAULT_SETTINGS);
        await saveSettings(DEFAULT_SETTINGS);
        
        showSaveStatus('Settings reset to defaults');
        
    } catch (error) {
        console.error('Failed to reset settings:', error);
        showSaveStatus('Failed to reset settings', true);
    }
}

function showSaveStatus(message, isError = false) {
    const statusElement = document.getElementById('save-status');
    statusElement.textContent = message;
    statusElement.className = `save-status ${isError ? 'error' : ''}`;
    
    // Clear status after 5 seconds
    setTimeout(() => {
        statusElement.textContent = '';
        statusElement.className = 'save-status';
    }, 5000);
}

// Debounce function to limit auto-save frequency
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Export settings for debugging
window.getSettings = loadSettings;
window.resetSettings = resetSettings;