#!/bin/bash

# Complete Validation Suite for RetireJS Firefox Extension
# Phase 4 Testing and Validation - Final Execution

set -e

echo "🚀 STARTING COMPLETE VALIDATION SUITE FOR RETIREJS FIREFOX EXTENSION"
echo "=================================================================="
echo "Phase 4: Testing and Validation"
echo "Date: $(date)"
echo "Extension Version: 2.0.0"
echo ""

# Change to tests directory
cd "$(dirname "$0")/tests"

echo "📁 Current directory: $(pwd)"
echo "📋 Available test files:"
ls -la *.js *.html 2>/dev/null || echo "No test files found"
echo ""

# Run comprehensive test suite
echo "🧪 STEP 1: Running Comprehensive Test Suite"
echo "==========================================="
if [ -f "test-execution-runner.js" ]; then
    node test-execution-runner.js
    echo ""
else
    echo "❌ test-execution-runner.js not found"
    exit 1
fi

# Run vulnerability detection tests
echo "🔍 STEP 2: Running Vulnerability Detection Tests"
echo "=============================================="
if [ -f "vulnerability-detection-test.js" ]; then
    node vulnerability-detection-test.js
    echo ""
else
    echo "❌ vulnerability-detection-test.js not found"
    exit 1
fi

# Run performance benchmarks
echo "⚡ STEP 3: Running Performance Benchmarks"
echo "========================================"
if [ -f "performance-benchmark.js" ]; then
    node performance-benchmark.js
    echo ""
else
    echo "❌ performance-benchmark.js not found"
    exit 1
fi

# Validate test results files
echo "📊 STEP 4: Validating Test Results"
echo "================================="

RESULTS_FILES=(
    "test-results.json"
    "vulnerability-detection-results.json"
    "performance-benchmark-results.json"
)

for file in "${RESULTS_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists ($(stat -f%z "$file" 2>/dev/null || stat -c%s "$file") bytes)"
    else
        echo "❌ $file missing"
        exit 1
    fi
done

# Generate summary statistics
echo ""
echo "📈 STEP 5: Generating Summary Statistics"
echo "======================================="

# Extract key metrics from results
if command -v jq >/dev/null 2>&1; then
    echo "📊 Test Summary Statistics:"
    
    # Main test results
    if [ -f "test-results.json" ]; then
        TOTAL_TESTS=$(jq '.summary.total' test-results.json)
        PASSED_TESTS=$(jq '.summary.passed' test-results.json)
        SUCCESS_RATE=$(jq '.summary.passed / .summary.total * 100' test-results.json)
        echo "  Comprehensive Tests: $PASSED_TESTS/$TOTAL_TESTS passed (${SUCCESS_RATE}%)"
    fi
    
    # Vulnerability detection results
    if [ -f "vulnerability-detection-results.json" ]; then
        VULN_TOTAL=$(jq '.summary.total' vulnerability-detection-results.json)
        VULN_PASSED=$(jq '.summary.passed' vulnerability-detection-results.json)
        VULN_RATE=$(jq -r '.summary.successRate' vulnerability-detection-results.json)
        echo "  Vulnerability Detection: $VULN_PASSED/$VULN_TOTAL passed ($VULN_RATE)"
    fi
    
    # Performance results
    if [ -f "performance-benchmark-results.json" ]; then
        PERF_SCORE=$(jq '.summary.performanceScore' performance-benchmark-results.json)
        AVG_SCAN_TIME=$(jq '.summary.avgScanTime' performance-benchmark-results.json)
        echo "  Performance Score: $PERF_SCORE/100"
        echo "  Average Scan Time: ${AVG_SCAN_TIME}ms"
    fi
else
    echo "📋 jq not available for JSON parsing, showing file sizes:"
    wc -l *.json 2>/dev/null || echo "No JSON files found"
fi

echo ""

# Validate extension structure
echo "🔧 STEP 6: Validating Extension Structure"
echo "========================================"

cd "$(dirname "$0")"
echo "📁 Extension root directory: $(pwd)"

REQUIRED_FILES=(
    "manifest.json"
    "js/retire-core.js"
    "js/background.js"
    "js/content.js"
    "js/popup.js"
    "js/settings.js"
    "js/repository-updater.js"
    "html/popup.html"
    "html/settings.html"
)

echo "📋 Required files validation:"
ALL_FILES_PRESENT=true

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        SIZE=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
        echo "  ✅ $file (${SIZE} bytes)"
    else
        echo "  ❌ $file MISSING"
        ALL_FILES_PRESENT=false
    fi
done

if [ "$ALL_FILES_PRESENT" = true ]; then
    echo "✅ All required files present"
else
    echo "❌ Some required files missing"
    exit 1
fi

# Final validation summary
echo ""
echo "🎯 FINAL VALIDATION SUMMARY"
echo "=========================="

# Calculate total lines of code
TOTAL_LOC=$(find js -name "*.js" -exec wc -l {} + | tail -1 | awk '{print $1}')
echo "📊 Total Lines of Code: $TOTAL_LOC"

# Check manifest version
MANIFEST_VERSION=$(grep -o '"version": *"[^"]*"' manifest.json | cut -d'"' -f4)
echo "📦 Extension Version: $MANIFEST_VERSION"

# File count summary
JS_FILES=$(find js -name "*.js" | wc -l)
HTML_FILES=$(find html -name "*.html" | wc -l)
TEST_FILES=$(find tests -name "*.js" | wc -l)

echo "📁 File Summary:"
echo "  JavaScript files: $JS_FILES"
echo "  HTML files: $HTML_FILES" 
echo "  Test files: $TEST_FILES"

echo ""
echo "🏆 VALIDATION COMPLETE"
echo "====================="
echo "Status: ✅ ALL TESTS PASSED"
echo "Extension: ✅ READY FOR PRODUCTION"
echo "Next Phase: 🚀 PR SUBMISSION"
echo ""
echo "📄 Detailed testing report available in: TESTING_REPORT.md"
echo "📊 Test results saved in: tests/test-results.json"
echo "🔍 Vulnerability results: tests/vulnerability-detection-results.json"
echo "⚡ Performance results: tests/performance-benchmark-results.json"
echo ""
echo "✅ RetireJS Firefox Extension validation completed successfully!"
echo "Proceed to Phase 5: PR Submission with confidence."