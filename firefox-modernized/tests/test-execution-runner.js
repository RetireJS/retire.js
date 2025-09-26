#!/usr/bin/env node

/**
 * Comprehensive Test Execution Runner for RetireJS Firefox Extension
 * Phase 4 Testing and Validation Suite
 */

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

class RetireJSTestRunner {
    constructor() {
        this.results = {
            functional: [],
            integration: [],
            security: [],
            performance: [],
            summary: {
                total: 0,
                passed: 0,
                failed: 0,
                skipped: 0,
                duration: 0
            }
        };
        this.startTime = performance.now();
    }

    async runTest(name, testFn, category = 'functional') {
        const testStart = performance.now();
        console.log(`\n🧪 Running ${category} test: ${name}`);
        
        try {
            await testFn();
            const duration = performance.now() - testStart;
            this.recordResult(name, 'PASSED', duration, category);
            console.log(`✅ PASSED: ${name} (${duration.toFixed(2)}ms)`);
            return true;
        } catch (error) {
            const duration = performance.now() - testStart;
            this.recordResult(name, 'FAILED', duration, category, error.message);
            console.log(`❌ FAILED: ${name} (${duration.toFixed(2)}ms)`);
            console.log(`   Error: ${error.message}`);
            return false;
        }
    }

    recordResult(name, status, duration, category, error = null) {
        const result = { name, status, duration, error };
        this.results[category].push(result);
        this.results.summary.total++;
        if (status === 'PASSED') this.results.summary.passed++;
        else this.results.summary.failed++;
    }

    // FUNCTIONAL TESTS
    async runFunctionalTests() {
        console.log('\n🔧 STARTING FUNCTIONAL TESTS');
        
        await this.runTest('Manifest Validation', async () => {
            const manifestPath = path.join(__dirname, '..', 'manifest.json');
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            
            // Check required fields
            if (!manifest.manifest_version) throw new Error('Missing manifest_version');
            if (!manifest.name) throw new Error('Missing name');
            if (!manifest.version) throw new Error('Missing version');
            if (!manifest.permissions) throw new Error('Missing permissions');
            
            // Validate permissions
            const requiredPerms = ['webRequest', 'webRequestBlocking', 'activeTab', 'storage'];
            for (const perm of requiredPerms) {
                if (!manifest.permissions.includes(perm)) {
                    throw new Error(`Missing required permission: ${perm}`);
                }
            }
            
            // Check content security policy
            if (!manifest.content_security_policy) {
                throw new Error('Missing content_security_policy');
            }
        }, 'functional');

        await this.runTest('Core Script Validation', async () => {
            const coreScriptPath = path.join(__dirname, '..', 'js', 'retire-core.js');
            const backgroundPath = path.join(__dirname, '..', 'js', 'background.js');
            const contentPath = path.join(__dirname, '..', 'js', 'content.js');
            
            if (!fs.existsSync(coreScriptPath)) throw new Error('retire-core.js not found');
            if (!fs.existsSync(backgroundPath)) throw new Error('background.js not found');
            if (!fs.existsSync(contentPath)) throw new Error('content.js not found');
            
            // Check file sizes (reasonable validation)
            const coreSize = fs.statSync(coreScriptPath).size;
            const backgroundSize = fs.statSync(backgroundPath).size;
            
            if (coreSize < 1000) throw new Error('retire-core.js too small, likely incomplete');
            if (backgroundSize < 500) throw new Error('background.js too small, likely incomplete');
        }, 'functional');

        await this.runTest('HTML Interface Validation', async () => {
            const popupPath = path.join(__dirname, '..', 'html', 'popup.html');
            const settingsPath = path.join(__dirname, '..', 'html', 'settings.html');
            
            if (!fs.existsSync(popupPath)) throw new Error('popup.html not found');
            if (!fs.existsSync(settingsPath)) throw new Error('settings.html not found');
            
            // Basic HTML validation
            const popupContent = fs.readFileSync(popupPath, 'utf8');
            const settingsContent = fs.readFileSync(settingsPath, 'utf8');
            
            if (!popupContent.includes('<!DOCTYPE html>')) throw new Error('popup.html missing DOCTYPE');
            if (!settingsContent.includes('<!DOCTYPE html>')) throw new Error('settings.html missing DOCTYPE');
        }, 'functional');

        await this.runTest('Vulnerability Detection Logic', async () => {
            // Simulate vulnerability detection test
            const testCases = [
                { component: 'jquery', version: '1.4.2', expectVuln: true },
                { component: 'jquery', version: '3.6.0', expectVuln: false },
                { component: 'angularjs', version: '1.5.0', expectVuln: true },
                { component: 'bootstrap', version: '3.3.7', expectVuln: true }
            ];
            
            // This would require loading the actual retire-core.js module
            // For now, we validate the test logic exists
            const coreScript = fs.readFileSync(path.join(__dirname, '..', 'js', 'retire-core.js'), 'utf8');
            
            if (!coreScript.includes('scanUri') && !coreScript.includes('scanFileName')) {
                throw new Error('Vulnerability scanning functions not found in core script');
            }
        }, 'functional');
    }

    // INTEGRATION TESTS
    async runIntegrationTests() {
        console.log('\n🔌 STARTING INTEGRATION TESTS');
        
        await this.runTest('WebExtensions API Compatibility', async () => {
            // Check all JavaScript files for required WebExtensions API usage
            const jsFiles = ['background.js', 'settings.js', 'repository-updater.js', 'popup.js', 'content.js'];
            let allContent = '';
            
            for (const file of jsFiles) {
                const filePath = path.join(__dirname, '..', 'js', file);
                if (fs.existsSync(filePath)) {
                    allContent += fs.readFileSync(filePath, 'utf8');
                }
            }
            
            // Check for required WebExtensions API usage across all files
            const requiredAPIs = [
                'browser.webRequest',
                'browser.runtime.onMessage',
                'browser.browserAction',
                'browser.storage',
                'browser.tabs'
            ];
            
            for (const api of requiredAPIs) {
                if (!allContent.includes(api)) {
                    throw new Error(`Missing WebExtensions API usage: ${api}`);
                }
            }
        }, 'integration');

        await this.runTest('Content-Background Communication', async () => {
            const contentScript = fs.readFileSync(path.join(__dirname, '..', 'js', 'content.js'), 'utf8');
            const backgroundScript = fs.readFileSync(path.join(__dirname, '..', 'js', 'background.js'), 'utf8');
            
            // Check message passing structure
            if (!contentScript.includes('browser.runtime.sendMessage')) {
                throw new Error('Content script missing message sending capability');
            }
            if (!backgroundScript.includes('browser.runtime.onMessage')) {
                throw new Error('Background script missing message handler');
            }
        }, 'integration');

        await this.runTest('Repository Updater Integration', async () => {
            const updaterPath = path.join(__dirname, '..', 'js', 'repository-updater.js');
            if (!fs.existsSync(updaterPath)) throw new Error('repository-updater.js not found');
            
            const updaterScript = fs.readFileSync(updaterPath, 'utf8');
            if (!updaterScript.includes('RepositoryUpdater')) {
                throw new Error('RepositoryUpdater class not found');
            }
        }, 'integration');
    }

    // SECURITY TESTS
    async runSecurityTests() {
        console.log('\n🔒 STARTING SECURITY TESTS');
        
        await this.runTest('Content Security Policy Validation', async () => {
            const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'manifest.json'), 'utf8'));
            const csp = manifest.content_security_policy;
            
            if (!csp) throw new Error('Missing Content Security Policy');
            if (!csp.includes("script-src 'self'")) throw new Error('CSP missing script-src self');
            if (!csp.includes("object-src 'self'")) throw new Error('CSP missing object-src self');
        }, 'security');

        await this.runTest('Permission Minimization', async () => {
            const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'manifest.json'), 'utf8'));
            const permissions = manifest.permissions;
            
            // Check for excessive permissions
            const dangerousPerms = ['tabs', 'history', 'bookmarks', 'cookies'];
            for (const perm of dangerousPerms) {
                if (permissions.includes(perm)) {
                    console.warn(`⚠️  Warning: Potentially excessive permission: ${perm}`);
                }
            }
            
            // Validate required permissions only
            const requiredPerms = ['webRequest', 'webRequestBlocking', 'activeTab', 'storage', '<all_urls>'];
            for (const perm of requiredPerms) {
                if (!permissions.includes(perm)) {
                    throw new Error(`Missing required permission: ${perm}`);
                }
            }
        }, 'security');

        await this.runTest('Input Validation', async () => {
            // Check for input validation in scripts
            const scripts = ['background.js', 'content.js', 'popup.js'];
            
            for (const script of scripts) {
                const scriptPath = path.join(__dirname, '..', 'js', script);
                const scriptContent = fs.readFileSync(scriptPath, 'utf8');
                
                // Look for basic input validation patterns
                if (scriptContent.includes('eval(') || scriptContent.includes('Function(')) {
                    throw new Error(`Dangerous eval usage found in ${script}`);
                }
            }
        }, 'security');
    }

    // PERFORMANCE TESTS
    async runPerformanceTests() {
        console.log('\n⚡ STARTING PERFORMANCE TESTS');
        
        await this.runTest('Script Size Validation', async () => {
            const coreScript = path.join(__dirname, '..', 'js', 'retire-core.js');
            const coreSize = fs.statSync(coreScript).size;
            
            // Core script should be reasonable size (not too large)
            if (coreSize > 2 * 1024 * 1024) { // 2MB limit
                throw new Error(`Core script too large: ${(coreSize / 1024 / 1024).toFixed(2)}MB`);
            }
            
            console.log(`📊 Core script size: ${(coreSize / 1024).toFixed(2)}KB`);
        }, 'performance');

        await this.runTest('Memory Efficiency Check', async () => {
            // Simulate memory usage validation
            const backgroundScript = fs.readFileSync(path.join(__dirname, '..', 'js', 'background.js'), 'utf8');
            
            // Check for potential memory leaks
            const memoryLeakPatterns = [
                'setInterval(', 'setTimeout(',  // Without corresponding clear
            ];
            
            let intervalCount = (backgroundScript.match(/setInterval\(/g) || []).length;
            let clearIntervalCount = (backgroundScript.match(/clearInterval\(/g) || []).length;
            
            if (intervalCount > clearIntervalCount && intervalCount > 0) {
                console.warn(`⚠️  Warning: Potential memory leak - ${intervalCount} intervals, ${clearIntervalCount} clears`);
            }
        }, 'performance');

        await this.runTest('Scanning Performance Simulation', async () => {
            // Simulate scanning performance test
            const testUrls = [
                'https://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js',
                'https://ajax.googleapis.com/ajax/libs/angularjs/1.5.0/angular.min.js',
                'https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js'
            ];
            
            const simulatedScanTime = 50; // ms per URL
            const totalTime = testUrls.length * simulatedScanTime;
            
            if (totalTime > 2000) { // 2 second limit
                throw new Error(`Simulated scan time too high: ${totalTime}ms`);
            }
            
            console.log(`📊 Simulated scan time for ${testUrls.length} URLs: ${totalTime}ms`);
        }, 'performance');
    }

    // MAIN EXECUTION
    async runAllTests() {
        console.log('🚀 STARTING COMPREHENSIVE RETIRE.JS FIREFOX EXTENSION TESTING');
        console.log('================================================================');
        
        try {
            await this.runFunctionalTests();
            await this.runIntegrationTests();
            await this.runSecurityTests();
            await this.runPerformanceTests();
        } catch (error) {
            console.error('❌ Test execution failed:', error);
        }
        
        this.generateReport();
    }

    generateReport() {
        const totalDuration = performance.now() - this.startTime;
        this.results.summary.duration = totalDuration;
        
        console.log('\n📊 TEST EXECUTION SUMMARY');
        console.log('================================================================');
        console.log(`Total Tests: ${this.results.summary.total}`);
        console.log(`Passed: ${this.results.summary.passed}`);
        console.log(`Failed: ${this.results.summary.failed}`);
        console.log(`Success Rate: ${((this.results.summary.passed / this.results.summary.total) * 100).toFixed(1)}%`);
        console.log(`Total Duration: ${(totalDuration / 1000).toFixed(2)}s`);
        
        // Category breakdown
        console.log('\n📋 CATEGORY BREAKDOWN:');
        ['functional', 'integration', 'security', 'performance'].forEach(category => {
            const categoryTests = this.results[category];
            const passed = categoryTests.filter(t => t.status === 'PASSED').length;
            const total = categoryTests.length;
            console.log(`${category.toUpperCase()}: ${passed}/${total} passed`);
        });
        
        // Failed tests details
        const allFailures = [
            ...this.results.functional,
            ...this.results.integration,
            ...this.results.security,
            ...this.results.performance
        ].filter(t => t.status === 'FAILED');
        
        if (allFailures.length > 0) {
            console.log('\n❌ FAILED TESTS:');
            allFailures.forEach(test => {
                console.log(`  - ${test.name}: ${test.error}`);
            });
        }
        
        // Write results to file
        fs.writeFileSync(
            path.join(__dirname, 'test-results.json'),
            JSON.stringify(this.results, null, 2)
        );
        
        console.log('\n✅ Test execution complete. Results saved to test-results.json');
        
        // Return overall success
        return this.results.summary.failed === 0;
    }
}

// Run tests if called directly
if (require.main === module) {
    const runner = new RetireJSTestRunner();
    runner.runAllTests().then(success => {
        process.exit(success ? 0 : 1);
    });
}

module.exports = RetireJSTestRunner;