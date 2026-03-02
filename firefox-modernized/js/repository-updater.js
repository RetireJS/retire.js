/* global browser, console */

class RepositoryUpdater {
    constructor() {
        this.REPOSITORY_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v3.json';
        this.UPDATE_INTERVAL = 6 * 60 * 60 * 1000; // 6 hours
        this.STORAGE_KEY = 'retirejs_repository';
        this.LAST_UPDATE_KEY = 'retirejs_last_update';
        
        this.repository = null;
        this.lastUpdate = null;
        
        this.init();
    }
    
    async init() {
        try {
            // Load repository from storage
            const stored = await browser.storage.local.get([this.STORAGE_KEY, this.LAST_UPDATE_KEY]);
            
            if (stored[this.STORAGE_KEY]) {
                this.repository = stored[this.STORAGE_KEY];
                this.lastUpdate = stored[this.LAST_UPDATE_KEY] || 0;
                console.log('Loaded repository from storage, last update:', new Date(this.lastUpdate));
            }
            
            // Check if update is needed
            if (this.shouldUpdate()) {
                await this.updateRepository();
            }
            
            // Set up periodic updates
            this.setupPeriodicUpdates();
            
        } catch (error) {
            console.error('Failed to initialize repository updater:', error);
            // Fall back to bundled repository
            this.loadBundledRepository();
        }
    }
    
    shouldUpdate() {
        if (!this.repository) return true;
        if (!this.lastUpdate) return true;
        
        const timeSinceUpdate = Date.now() - this.lastUpdate;
        return timeSinceUpdate > this.UPDATE_INTERVAL;
    }
    
    async updateRepository() {
        console.log('Updating vulnerability repository...');
        
        try {
            const response = await fetch(this.REPOSITORY_URL, {
                headers: {
                    'Cache-Control': 'no-cache'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const repositoryData = await response.json();
            
            // Validate repository structure
            if (!this.validateRepository(repositoryData)) {
                throw new Error('Invalid repository structure');
            }
            
            // Update in memory
            this.repository = repositoryData;
            this.lastUpdate = Date.now();
            
            // Save to storage
            await browser.storage.local.set({
                [this.STORAGE_KEY]: this.repository,
                [this.LAST_UPDATE_KEY]: this.lastUpdate
            });
            
            console.log('Repository updated successfully at', new Date(this.lastUpdate));
            
            // Notify background script
            browser.runtime.sendMessage({
                type: 'repository-updated',
                repository: this.repository
            }).catch(() => {
                // Ignore errors if background script isn't listening
            });
            
        } catch (error) {
            console.error('Failed to update repository:', error);
            
            // If we don't have any repository, load the bundled one
            if (!this.repository) {
                this.loadBundledRepository();
            }
        }
    }
    
    validateRepository(repo) {
        if (!repo || typeof repo !== 'object') return false;
        
        // Check if it has the expected structure
        const sampleKey = Object.keys(repo)[0];
        if (!sampleKey) return false;
        
        const sampleEntry = repo[sampleKey];
        if (!sampleEntry || typeof sampleEntry !== 'object') return false;
        
        // Should have vulnerabilities or extractors
        if (!sampleEntry.vulnerabilities && !sampleEntry.extractors) return false;
        
        return true;
    }
    
    loadBundledRepository() {
        try {
            // Use the bundled repository from retire-core.js
            if (typeof retirechrome !== 'undefined' && retirechrome.repo) {
                this.repository = retirechrome.repo;
                this.lastUpdate = Date.now();
                console.log('Loaded bundled repository');
            } else {
                console.error('No bundled repository available');
            }
        } catch (error) {
            console.error('Failed to load bundled repository:', error);
        }
    }
    
    setupPeriodicUpdates() {
        // Check for updates every hour
        setInterval(() => {
            if (this.shouldUpdate()) {
                this.updateRepository();
            }
        }, 60 * 60 * 1000); // 1 hour
    }
    
    getRepository() {
        return this.repository;
    }
    
    getLastUpdate() {
        return this.lastUpdate;
    }
    
    async forceUpdate() {
        await this.updateRepository();
        return this.repository;
    }
    
    // Get repository statistics
    getStats() {
        if (!this.repository) return null;
        
        const entries = Object.keys(this.repository);
        let totalVulnerabilities = 0;
        let totalExtractors = 0;
        
        entries.forEach(key => {
            const entry = this.repository[key];
            if (entry.vulnerabilities) {
                totalVulnerabilities += entry.vulnerabilities.length;
            }
            if (entry.extractors) {
                if (entry.extractors.func) totalExtractors += entry.extractors.func.length;
                if (entry.extractors.filename) totalExtractors += entry.extractors.filename.length;
                if (entry.extractors.filecontent) totalExtractors += entry.extractors.filecontent.length;
                if (entry.extractors.uri) totalExtractors += entry.extractors.uri.length;
                if (entry.extractors.ast) totalExtractors += entry.extractors.ast.length;
            }
        });
        
        return {
            libraries: entries.length,
            vulnerabilities: totalVulnerabilities,
            extractors: totalExtractors,
            lastUpdate: this.lastUpdate
        };
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RepositoryUpdater;
} else {
    // Browser environment
    window.RepositoryUpdater = RepositoryUpdater;
}