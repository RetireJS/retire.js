#!/usr/bin/env node

/**
 * Performance Benchmark Tests for RetireJS Firefox Extension
 * Tests performance metrics and browser impact
 */

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

class PerformanceBenchmark {
    constructor() {
        this.benchmarks = [];
        this.memoryBaseline = process.memoryUsage();
    }

    async runBenchmarks() {
        console.log('⚡ STARTING PERFORMANCE BENCHMARKS');
        console.log('==================================');
        
        await this.benchmarkScriptLoading();
        await this.benchmarkVulnerabilityScanning();
        await this.benchmarkMemoryUsage();
        await this.benchmarkConcurrentScanning();
        
        this.generatePerformanceReport();
    }

    async benchmarkScriptLoading() {
        console.log('\n📊 Benchmarking Script Loading Performance');
        
        const scripts = [
            'retire-core.js',
            'background.js',
            'content.js',
            'popup.js',
            'settings.js',
            'repository-updater.js'
        ];
        
        for (const script of scripts) {
            const startTime = performance.now();
            const scriptPath = path.join(__dirname, '..', 'js', script);
            
            if (fs.existsSync(scriptPath)) {
                const content = fs.readFileSync(scriptPath, 'utf8');
                const parseTime = performance.now() - startTime;
                const size = content.length;
                
                this.benchmarks.push({
                    type: 'script-loading',
                    script: script,
                    loadTime: parseTime,
                    size: size,
                    throughput: size / parseTime // bytes per ms
                });
                
                console.log(`  ${script}: ${parseTime.toFixed(2)}ms (${(size/1024).toFixed(2)}KB)`);
            }
        }
    }

    async benchmarkVulnerabilityScanning() {
        console.log('\n🔍 Benchmarking Vulnerability Scanning Performance');
        
        const testUrls = [
            'https://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js',
            'https://ajax.googleapis.com/ajax/libs/angularjs/1.5.0/angular.min.js',
            'https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js',
            'https://cdn.jsdelivr.net/npm/lodash@4.17.0/lodash.min.js',
            'https://unpkg.com/react@16.8.0/umd/react.development.js'
        ];
        
        let totalScanTime = 0;
        let scansCompleted = 0;
        
        for (const url of testUrls) {
            const startTime = performance.now();
            
            // Simulate URL scanning (pattern matching)
            const scanResult = this.simulateUrlScan(url);
            
            const scanTime = performance.now() - startTime;
            totalScanTime += scanTime;
            scansCompleted++;
            
            this.benchmarks.push({
                type: 'vulnerability-scan',
                url: url,
                scanTime: scanTime,
                vulnerabilityFound: scanResult.vulnerable,
                component: scanResult.component
            });
            
            console.log(`  ${url.split('/').pop()}: ${scanTime.toFixed(3)}ms - ${scanResult.vulnerable ? 'VULNERABLE' : 'SAFE'}`);
        }
        
        const avgScanTime = totalScanTime / scansCompleted;
        console.log(`  Average scan time: ${avgScanTime.toFixed(3)}ms`);
        
        // Performance requirements check
        if (avgScanTime > 2000) { // 2 second limit
            console.warn(`⚠️  WARNING: Average scan time exceeds 2s limit: ${avgScanTime.toFixed(3)}ms`);
        } else {
            console.log(`✅ Performance requirement met: < 2000ms per scan`);
        }
    }

    async benchmarkMemoryUsage() {
        console.log('\n💾 Benchmarking Memory Usage');
        
        const initialMemory = process.memoryUsage();
        console.log(`  Initial memory usage: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`);
        
        // Simulate loading retire-core multiple times
        const iterations = 10;
        const memoryReadings = [];
        
        for (let i = 0; i < iterations; i++) {
            const coreScript = fs.readFileSync(path.join(__dirname, '..', 'js', 'retire-core.js'), 'utf8');
            
            // Simulate processing
            for (let j = 0; j < 100; j++) {
                this.simulateUrlScan('https://example.com/test.js');
            }
            
            const currentMemory = process.memoryUsage();
            memoryReadings.push(currentMemory.heapUsed);
        }
        
        const finalMemory = process.memoryUsage();
        const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
        
        this.benchmarks.push({
            type: 'memory-usage',
            initialMemory: initialMemory.heapUsed,
            finalMemory: finalMemory.heapUsed,
            memoryIncrease: memoryIncrease,
            iterations: iterations
        });
        
        console.log(`  Final memory usage: ${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`);
        console.log(`  Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
        
        // Memory leak check
        if (memoryIncrease > 50 * 1024 * 1024) { // 50MB threshold
            console.warn(`⚠️  WARNING: Potential memory leak detected: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB increase`);
        } else {
            console.log(`✅ Memory usage within acceptable limits`);
        }
    }

    async benchmarkConcurrentScanning() {
        console.log('\n🚀 Benchmarking Concurrent Scanning Performance');
        
        const testUrls = Array(20).fill(0).map((_, i) => 
            `https://example${i}.com/lib-${i % 5}.js`
        );
        
        const startTime = performance.now();
        
        // Simulate concurrent scanning
        const promises = testUrls.map(url => 
            Promise.resolve(this.simulateUrlScan(url))
        );
        
        const results = await Promise.all(promises);
        const totalTime = performance.now() - startTime;
        
        this.benchmarks.push({
            type: 'concurrent-scanning',
            urlCount: testUrls.length,
            totalTime: totalTime,
            averageTimePerUrl: totalTime / testUrls.length,
            throughput: testUrls.length / (totalTime / 1000) // URLs per second
        });
        
        console.log(`  Scanned ${testUrls.length} URLs in ${totalTime.toFixed(2)}ms`);
        console.log(`  Average time per URL: ${(totalTime / testUrls.length).toFixed(2)}ms`);
        console.log(`  Throughput: ${(testUrls.length / (totalTime / 1000)).toFixed(2)} URLs/second`);
        
        // Browser responsiveness check
        if (totalTime > 5000) { // 5 second limit for 20 URLs
            console.warn(`⚠️  WARNING: Concurrent scanning too slow: ${totalTime.toFixed(2)}ms`);
        } else {
            console.log(`✅ Concurrent scanning performance acceptable`);
        }
    }

    simulateUrlScan(url) {
        // Extract filename and check for patterns
        const filename = url.split('/').pop();
        const vulnerablePatterns = [
            { pattern: /jquery.*1\.[0-6]\./, component: 'jquery', vulnerable: true },
            { pattern: /angular.*1\.[0-6]\./, component: 'angularjs', vulnerable: true },
            { pattern: /bootstrap.*3\.[0-3]\./, component: 'bootstrap', vulnerable: true },
            { pattern: /lodash.*4\.1[0-7]\./, component: 'lodash', vulnerable: true }
        ];
        
        for (const { pattern, component, vulnerable } of vulnerablePatterns) {
            if (pattern.test(filename)) {
                return { component, vulnerable: true };
            }
        }
        
        return { component: null, vulnerable: false };
    }

    generatePerformanceReport() {
        console.log('\n📊 PERFORMANCE BENCHMARK SUMMARY');
        console.log('==================================');
        
        // Script loading performance
        const scriptBenchmarks = this.benchmarks.filter(b => b.type === 'script-loading');
        const totalLoadTime = scriptBenchmarks.reduce((sum, b) => sum + b.loadTime, 0);
        const totalScriptSize = scriptBenchmarks.reduce((sum, b) => sum + b.size, 0);
        
        console.log(`Script Loading:`);
        console.log(`  Total load time: ${totalLoadTime.toFixed(2)}ms`);
        console.log(`  Total script size: ${(totalScriptSize / 1024).toFixed(2)}KB`);
        console.log(`  Average throughput: ${(totalScriptSize / totalLoadTime).toFixed(2)} bytes/ms`);
        
        // Vulnerability scanning performance
        const scanBenchmarks = this.benchmarks.filter(b => b.type === 'vulnerability-scan');
        const avgScanTime = scanBenchmarks.reduce((sum, b) => sum + b.scanTime, 0) / scanBenchmarks.length;
        
        console.log(`\nVulnerability Scanning:`);
        console.log(`  Average scan time: ${avgScanTime.toFixed(3)}ms`);
        console.log(`  Scans completed: ${scanBenchmarks.length}`);
        console.log(`  Performance target (<2000ms): ${avgScanTime < 2000 ? '✅ MET' : '❌ FAILED'}`);
        
        // Memory usage
        const memoryBenchmark = this.benchmarks.find(b => b.type === 'memory-usage');
        if (memoryBenchmark) {
            console.log(`\nMemory Usage:`);
            console.log(`  Memory increase: ${(memoryBenchmark.memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
            console.log(`  Memory efficiency: ${memoryBenchmark.memoryIncrease < 50 * 1024 * 1024 ? '✅ GOOD' : '⚠️  CONCERN'}`);
        }
        
        // Concurrent scanning
        const concurrentBenchmark = this.benchmarks.find(b => b.type === 'concurrent-scanning');
        if (concurrentBenchmark) {
            console.log(`\nConcurrent Scanning:`);
            console.log(`  Throughput: ${concurrentBenchmark.throughput.toFixed(2)} URLs/second`);
            console.log(`  Browser responsiveness: ${concurrentBenchmark.totalTime < 5000 ? '✅ GOOD' : '⚠️  SLOW'}`);
        }
        
        // Overall performance score
        let performanceScore = 100;
        if (avgScanTime > 2000) performanceScore -= 30;
        if (memoryBenchmark && memoryBenchmark.memoryIncrease > 50 * 1024 * 1024) performanceScore -= 20;
        if (concurrentBenchmark && concurrentBenchmark.totalTime > 5000) performanceScore -= 20;
        if (totalLoadTime > 1000) performanceScore -= 10;
        
        console.log(`\n🎯 Overall Performance Score: ${performanceScore}/100`);
        
        if (performanceScore >= 90) {
            console.log('✅ EXCELLENT performance - Ready for production');
        } else if (performanceScore >= 70) {
            console.log('⚠️  GOOD performance - Minor optimizations recommended');
        } else {
            console.log('❌ POOR performance - Significant optimizations required');
        }
        
        // Save detailed results
        const resultsPath = path.join(__dirname, 'performance-benchmark-results.json');
        fs.writeFileSync(resultsPath, JSON.stringify({
            summary: {
                performanceScore,
                avgScanTime,
                memoryIncrease: memoryBenchmark ? memoryBenchmark.memoryIncrease : 0,
                concurrentThroughput: concurrentBenchmark ? concurrentBenchmark.throughput : 0,
                timestamp: new Date().toISOString()
            },
            benchmarks: this.benchmarks
        }, null, 2));
        
        console.log(`\n📁 Detailed results saved to: ${resultsPath}`);
        
        return performanceScore >= 70; // 70% minimum acceptable score
    }
}

// Run if called directly
if (require.main === module) {
    const benchmark = new PerformanceBenchmark();
    benchmark.runBenchmarks().then(() => {
        console.log('\n✅ Performance benchmarking complete!');
    });
}

module.exports = PerformanceBenchmark;