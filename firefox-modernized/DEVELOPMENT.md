# Development Guide - retire.js Firefox Extension

This guide provides detailed information for developers working on the retire.js Firefox extension.

## Development Environment Setup

### Prerequisites

1. **Firefox Developer Edition** (recommended) or Firefox 55+
2. **Git** for version control
3. **Text Editor/IDE** with JavaScript support
4. **Node.js** (optional, for advanced tooling)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/RetireJS/retire.js.git
cd retire.js/firefox-modernized

# Create development branch
git checkout -b feature/your-feature-name

# Load extension in Firefox
# 1. Open about:debugging
# 2. Click "This Firefox"
# 3. Click "Load Temporary Add-on"
# 4. Select manifest.json
```

## Architecture Deep Dive

### Extension Components

#### 1. Background Script (`js/background.js`)
**Purpose**: Central coordination and vulnerability scanning logic

**Key Functions**:
- Monitors web requests for JavaScript files
- Performs vulnerability scanning using multiple methods
- Manages tab state and vulnerability counts
- Handles communication between components

**Code Structure**:
```javascript
// Core scanning pipeline
webRequest.onCompleted → scanScript() → performContentScan() → reportVulnerabilities()

// Message handling
runtime.onMessage → messageHandler() → various action handlers
```

#### 2. Content Script (`js/content.js`)
**Purpose**: Page-level scanning and console output

**Key Functions**:
- Scans inline scripts
- Monitors dynamic script injection
- Outputs detailed vulnerability warnings to console
- Communicates scan results to background script

**Injection Points**:
- Document start (for early detection)
- DOM mutations (for dynamic content)
- Element.appendChild override (for programmatic injection)

#### 3. Repository Updater (`js/repository-updater.js`)
**Purpose**: Manages vulnerability database

**Key Functions**:
- Downloads latest vulnerability data
- Validates repository structure
- Handles update scheduling and caching
- Provides repository statistics

**Update Cycle**:
```
Init → Load from storage → Check if update needed → Download → Validate → Save → Schedule next
```

#### 4. Popup Interface (`js/popup.js`)
**Purpose**: User interface for current page status

**Components**:
- Current vulnerability count
- Scan toggle controls
- Detected vulnerabilities list
- Quick action buttons

#### 5. Settings Panel (`js/settings.js`)
**Purpose**: Extension configuration

**Settings Categories**:
- Scanning options
- Repository management
- Performance settings
- Privacy controls
- Advanced options

### Data Flow

```
Web Request → Background Script → Content Script → User Interface
     ↓              ↓                   ↓              ↑
Vulnerability → Repository → Console Warning → Status Update
Detection      Lookup      Display         Popup/Badge
```

## Core Algorithms

### Vulnerability Detection Pipeline

#### 1. URL-based Detection
```javascript
function scanUri(url, repository) {
    // Extract library name and version from CDN URLs
    const patterns = repository.extractors.uri;
    for (const pattern of patterns) {
        const match = url.match(pattern.regex);
        if (match) {
            return checkVulnerabilities(pattern.component, match.groups.version);
        }
    }
    return [];
}
```

#### 2. Filename Detection
```javascript
function scanFileName(filename, repository) {
    // Match filename patterns like "jquery-1.4.2.min.js"
    const patterns = repository.extractors.filename;
    // Similar pattern matching logic
}
```

#### 3. Content-based Detection
```javascript
function scanFileContent(content, repository) {
    // Hash-based detection
    const hash = sha1(content);
    const hashResults = repository.extractors.filecontent[hash] || [];
    
    // Function signature detection
    const funcResults = detectFunctionSignatures(content, repository);
    
    return [...hashResults, ...funcResults];
}
```

#### 4. AST-based Detection
```javascript
function performASTScan(content, repository) {
    // Parse JavaScript to AST
    // Extract version patterns using astronomical library
    const queries = buildASTQueries(repository);
    const results = multiQuery(content, queries);
    return processASTResults(results, repository);
}
```

### Performance Optimizations

#### 1. Caching Strategy
```javascript
class VulnerabilityCache {
    constructor() {
        this.urlCache = new Map();
        this.hashCache = new Map();
        this.maxSize = 1000;
    }
    
    get(key, type) {
        const cache = type === 'url' ? this.urlCache : this.hashCache;
        return cache.get(key);
    }
    
    set(key, value, type) {
        const cache = type === 'url' ? this.urlCache : this.hashCache;
        if (cache.size >= this.maxSize) {
            const firstKey = cache.keys().next().value;
            cache.delete(firstKey);
        }
        cache.set(key, value);
    }
}
```

#### 2. Request Filtering
```javascript
function shouldScanRequest(details) {
    // Skip non-script resources
    if (details.type !== 'script') return false;
    
    // Skip failed requests
    if (details.statusCode !== 200) return false;
    
    // Skip very large files
    const contentLength = getContentLength(details.responseHeaders);
    if (contentLength > MAX_FILE_SIZE) return false;
    
    return true;
}
```

#### 3. Async Processing
```javascript
async function scanScript(details) {
    // Non-blocking URL/filename scan
    const quickResults = await performQuickScan(details);
    if (quickResults.length > 0) {
        reportVulnerabilities(quickResults, details);
        return;
    }
    
    // Background content scan
    setTimeout(async () => {
        const contentResults = await performContentScan(details);
        if (contentResults.length > 0) {
            reportVulnerabilities(contentResults, details);
        }
    }, 0);
}
```

## Testing Strategy

### Test Categories

#### 1. Unit Tests
**Purpose**: Test individual functions and components

**Examples**:
- URL parsing functions
- Vulnerability detection algorithms
- Settings management
- Repository updater logic

**Structure**:
```javascript
// tests/unit/test-url-parsing.js
describe('URL Parsing', () => {
    test('extracts filename from CDN URLs', () => {
        const url = 'https://cdn.example.com/jquery-1.4.2.min.js';
        const filename = getFileName(url);
        expect(filename).toBe('jquery-1.4.2.min.js');
    });
});
```

#### 2. Integration Tests
**Purpose**: Test component interaction

**Examples**:
- Background-content script communication
- Repository update process
- Settings persistence
- Extension loading/unloading

#### 3. End-to-End Tests
**Purpose**: Test complete user workflows

**Examples**:
- Vulnerability detection on real websites
- Settings changes affecting behavior
- Database updates
- User interface interactions

### Test Infrastructure

#### Test Page Generator
```javascript
function generateTestPage(libraries) {
    const html = `
        <!DOCTYPE html>
        <html>
        <head><title>Test Page</title></head>
        <body>
            ${libraries.map(lib => 
                `<script src="${lib.url}"></script>`
            ).join('\n')}
        </body>
        </html>
    `;
    return html;
}
```

#### Mock Framework
```javascript
class MockBrowser {
    constructor() {
        this.storage = new MockStorage();
        this.tabs = new MockTabs();
        this.runtime = new MockRuntime();
    }
    
    reset() {
        // Reset all mocks to initial state
    }
}
```

## Debugging Techniques

### Browser Developer Tools

#### 1. Extension Debugging
```javascript
// Enable debug mode in background script
const DEBUG = true;

function debugLog(...args) {
    if (DEBUG) {
        console.log('[retire.js]', ...args);
    }
}
```

#### 2. about:debugging
- Navigate to `about:debugging#/runtime/this-firefox`
- Click "Inspect" next to retire.js extension
- Access background script console and debugger

#### 3. Content Script Debugging
- Open Developer Tools on target page
- Console messages from content script appear here
- Use `debugger;` statements for breakpoints

### Performance Profiling

#### 1. Timing Measurements
```javascript
async function scanWithTiming(details) {
    const start = performance.now();
    const results = await performScan(details);
    const duration = performance.now() - start;
    
    console.log(`Scan completed in ${duration}ms`);
    return results;
}
```

#### 2. Memory Usage
```javascript
function logMemoryUsage() {
    if (performance.memory) {
        console.log('Memory usage:', {
            used: performance.memory.usedJSHeapSize,
            total: performance.memory.totalJSHeapSize,
            limit: performance.memory.jsHeapSizeLimit
        });
    }
}
```

## Common Development Patterns

### Message Passing
```javascript
// Background script
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
        case 'scan-request':
            handleScanRequest(message).then(sendResponse);
            return true; // Keep channel open for async response
        default:
            sendResponse({ error: 'Unknown message type' });
    }
});

// Content script
async function requestScan(content) {
    try {
        const response = await browser.runtime.sendMessage({
            type: 'scan-request',
            content: content
        });
        return response;
    } catch (error) {
        console.error('Failed to request scan:', error);
        return null;
    }
}
```

### Storage Management
```javascript
class SettingsManager {
    constructor() {
        this.cache = new Map();
    }
    
    async get(key, defaultValue) {
        if (this.cache.has(key)) {
            return this.cache.get(key);
        }
        
        const stored = await browser.storage.local.get(key);
        const value = stored[key] || defaultValue;
        this.cache.set(key, value);
        return value;
    }
    
    async set(key, value) {
        this.cache.set(key, value);
        await browser.storage.local.set({ [key]: value });
    }
}
```

### Error Handling
```javascript
function withErrorHandling(fn) {
    return async (...args) => {
        try {
            return await fn(...args);
        } catch (error) {
            console.error(`Error in ${fn.name}:`, error);
            // Report to background script if needed
            browser.runtime.sendMessage({
                type: 'error-report',
                error: error.message,
                function: fn.name
            });
            return null;
        }
    };
}

// Usage
const safeScanScript = withErrorHandling(scanScript);
```

## Code Quality Guidelines

### JavaScript Style

#### 1. Modern ES6+ Features
```javascript
// Use const/let instead of var
const config = { timeout: 10000 };
let currentScan = null;

// Use arrow functions for callbacks
urls.map(url => scanUrl(url));

// Use async/await instead of .then()
async function updateRepository() {
    try {
        const response = await fetch(REPOSITORY_URL);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Update failed:', error);
        throw error;
    }
}
```

#### 2. Error Handling
```javascript
// Always handle promise rejections
function scanWithFallback(url) {
    return performScan(url)
        .catch(error => {
            console.warn('Scan failed, using fallback:', error);
            return performFallbackScan(url);
        });
}

// Validate inputs
function validateUrl(url) {
    if (!url || typeof url !== 'string') {
        throw new Error('Invalid URL provided');
    }
    
    try {
        new URL(url);
    } catch {
        throw new Error('Malformed URL');
    }
}
```

#### 3. Documentation
```javascript
/**
 * Scans a JavaScript file for known vulnerabilities
 * @param {Object} details - Request details from webRequest API
 * @param {string} details.url - The URL of the JavaScript file
 * @param {number} details.tabId - The tab ID where the request originated
 * @returns {Promise<Array>} Array of vulnerability objects
 */
async function scanScript(details) {
    // Implementation
}
```

### Performance Guidelines

#### 1. Minimize Main Thread Blocking
```javascript
// Good: Use setTimeout for heavy processing
function processLargeDataset(data) {
    const chunks = chunkArray(data, 100);
    
    function processChunk(index) {
        if (index >= chunks.length) return;
        
        const chunk = chunks[index];
        // Process chunk
        
        setTimeout(() => processChunk(index + 1), 0);
    }
    
    processChunk(0);
}
```

#### 2. Efficient Data Structures
```javascript
// Use Map/Set for better performance
const vulnerabilityCache = new Map();
const processedUrls = new Set();

// Avoid repeated array operations
const results = [];
for (const item of items) {
    results.push(processItem(item)); // Good
}
// Instead of: items.map().filter().reduce()
```

## Release Process

### Version Management

#### 1. Semantic Versioning
- **Major** (X.0.0): Breaking changes, API changes
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, security updates

#### 2. Release Checklist
```markdown
- [ ] All tests pass
- [ ] Manual testing completed
- [ ] Performance benchmarks acceptable
- [ ] Documentation updated
- [ ] Version number updated in manifest.json
- [ ] Changelog updated
- [ ] Browser compatibility verified
```

### Deployment

#### 1. AMO (addons.mozilla.org) Submission
1. Create addon submission package
2. Upload to AMO developer dashboard
3. Wait for automated and manual review
4. Address any review feedback
5. Publication approval

#### 2. Self-hosted Distribution
1. Sign extension with AMO
2. Host .xpi file on secure server
3. Provide installation instructions
4. Set up update manifest for auto-updates

## Troubleshooting Common Issues

### Extension Won't Load

#### Symptoms
- Extension doesn't appear in about:addons
- Error messages in Browser Console

#### Solutions
1. Check manifest.json syntax
2. Verify file permissions
3. Check for conflicting extensions
4. Review Firefox version compatibility

### Scanning Not Working

#### Symptoms
- No vulnerability warnings in console
- Badge not updating
- Settings show scanning disabled

#### Debug Steps
1. Check background script console for errors
2. Verify webRequest permission granted
3. Test with known vulnerable libraries
4. Check repository update status

### Performance Issues

#### Symptoms
- Browser slowdown when visiting sites
- High CPU usage
- Memory leaks

#### Solutions
1. Disable deep scanning temporarily
2. Increase file size limits
3. Check for infinite loops in scanning logic
4. Profile memory usage

## Contributing Guidelines

### Pull Request Process

1. **Fork and Branch**
   ```bash
   git checkout -b feature/description
   ```

2. **Development**
   - Follow code style guidelines
   - Add tests for new features
   - Update documentation

3. **Testing**
   ```bash
   # Run test suite
   firefox tests/test-runner.html
   
   # Manual testing
   # Load extension and test on various sites
   ```

4. **Submit PR**
   - Descriptive title and description
   - Link to related issues
   - Include testing notes

### Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests cover new functionality
- [ ] Documentation is updated
- [ ] Performance impact is acceptable
- [ ] Security considerations addressed
- [ ] Browser compatibility maintained

This development guide provides the foundation for working on the retire.js Firefox extension. For specific questions or issues, please refer to the project's GitHub issues or start a discussion.