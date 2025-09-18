# retire.js Firefox Extension (Modernized)

A modern WebExtensions implementation of the retire.js vulnerability scanner for Firefox.

## Overview

This extension automatically scans JavaScript libraries on websites for known security vulnerabilities. It provides real-time vulnerability detection with minimal performance impact and comprehensive reporting.

## Features

### Core Functionality
- ✅ **Real-time Scanning**: Automatically scans JavaScript files as they load
- ✅ **Multiple Detection Methods**: URL, filename, hash, and AST-based detection
- ✅ **Badge Notifications**: Shows vulnerability count in address bar
- ✅ **Console Warnings**: Detailed vulnerability information in developer console
- ✅ **Modern WebExtensions**: Compatible with Firefox 55+ using WebExtensions API

### Advanced Features
- ✅ **Deep Scanning**: Advanced AST analysis for accurate detection
- ✅ **Auto-updating Database**: Vulnerability database updates every 6 hours
- ✅ **Settings Panel**: Comprehensive configuration options
- ✅ **Performance Optimized**: Minimal impact on browsing experience
- ✅ **Privacy Focused**: All scanning done locally, no data sent to external servers

## Installation

### From Source (Development)

1. **Download the Extension**
   ```bash
   git clone https://github.com/RetireJS/retire.js.git
   cd retire.js/firefox-modernized
   ```

2. **Load in Firefox**
   - Open Firefox and navigate to `about:debugging`
   - Click "This Firefox" in the sidebar
   - Click "Load Temporary Add-on"
   - Select the `manifest.json` file from the extension directory

3. **Verify Installation**
   - The retire.js icon should appear in the toolbar
   - Visit a test page with vulnerable libraries to see it in action

### From Mozilla Add-ons (Coming Soon)
The extension will be available on the Mozilla Add-ons store once development is complete.

## Usage

### Basic Usage

1. **Automatic Scanning**: The extension automatically scans all JavaScript files on websites you visit
2. **Badge Notifications**: A red badge appears on the extension icon showing the number of vulnerabilities
3. **Console Output**: Open Developer Tools (F12) → Console to see detailed vulnerability information
4. **Popup Interface**: Click the extension icon to see a summary of detected vulnerabilities

### Advanced Configuration

1. **Open Settings**: Click the extension icon → Settings
2. **Configure Scanning**:
   - Enable/disable vulnerability scanning
   - Toggle deep scanning (AST analysis)
   - Adjust performance settings
3. **Database Management**:
   - Force update vulnerability database
   - Configure auto-update frequency

## Technical Details

### Architecture

```
firefox-modernized/
├── manifest.json              # Extension manifest (WebExtensions v2)
├── js/
│   ├── retire-core.js         # Core vulnerability detection logic
│   ├── background.js          # Background script (service worker equivalent)
│   ├── content.js            # Content script for page scanning
│   ├── popup.js              # Popup interface logic
│   ├── settings.js           # Settings page logic
│   └── repository-updater.js # Vulnerability database management
├── html/
│   ├── popup.html            # Extension popup interface
│   └── settings.html         # Settings page
├── css/
│   ├── popup.css             # Popup styles
│   └── settings.css          # Settings page styles
├── icons/                    # Extension icons
└── tests/                    # Test suite
```

### Detection Methods

1. **URL-based Detection**: Matches CDN URLs against known vulnerable versions
2. **Filename Detection**: Analyzes JavaScript filenames for version patterns
3. **Hash-based Detection**: Uses SHA1 hashes to identify exact vulnerable files
4. **AST-based Detection**: Advanced code analysis for library detection and version extraction

### Performance Considerations

- **Asynchronous Processing**: All scanning operations are non-blocking
- **Selective Scanning**: Only JavaScript resources are analyzed
- **Size Limits**: Large files (>5MB default) are skipped
- **Timeout Protection**: Scans timeout after 10 seconds to prevent blocking
- **Caching**: Results are cached to avoid re-scanning identical resources

## Development

### Prerequisites

- Firefox 55 or later
- Basic knowledge of WebExtensions API
- Node.js (for building from source)

### Building

```bash
# Clone the repository
git clone https://github.com/RetireJS/retire.js.git
cd retire.js/firefox-modernized

# The extension is ready to load directly
# No build process required for the basic version
```

### Testing

1. **Load Test Page**:
   ```bash
   firefox tests/fixtures/vulnerable-test-page.html
   ```

2. **Run Test Suite**:
   ```bash
   firefox tests/test-runner.html
   ```

3. **Manual Testing**:
   - Visit websites with known vulnerable libraries
   - Check console output for vulnerability warnings
   - Verify badge counts and popup information

### API Reference

#### Background Script Messages

```javascript
// Get extension status
browser.runtime.sendMessage({ type: 'get-status' });
// Returns: { scanEnabled: boolean, deepScanEnabled: boolean, vulnerabilityCount: number }

// Toggle scanning
browser.runtime.sendMessage({ type: 'toggle-scan' });
// Returns: { scanEnabled: boolean }

// Get repository statistics
browser.runtime.sendMessage({ type: 'get-repository-stats' });
// Returns: { libraries: number, vulnerabilities: number, extractors: number, lastUpdate: timestamp }

// Force repository update
browser.runtime.sendMessage({ type: 'force-repository-update' });
// Returns: { success: boolean, error?: string }
```

#### Content Script Messages

```javascript
// Get detected vulnerabilities for current page
browser.tabs.sendMessage(tabId, { type: 'get-detected' });
// Returns: Array of vulnerability objects

// Vulnerability notification
{
  type: 'vulnerability-found',
  url: 'https://example.com/jquery.min.js',
  results: [
    {
      component: 'jquery',
      version: '1.4.2',
      vulnerabilities: [
        {
          severity: 'medium',
          info: ['XSS vulnerability in jQuery 1.4.2']
        }
      ]
    }
  ]
}
```

## Security Considerations

### Privacy
- **Local Processing**: All vulnerability scanning is performed locally
- **No Data Collection**: The extension does not collect or transmit user data
- **Minimal Permissions**: Only requests necessary permissions for functionality

### Performance
- **Non-blocking**: Scanning does not interfere with page loading
- **Resource Limits**: Large files are skipped to prevent performance issues
- **Error Handling**: Robust error handling prevents extension crashes

### Security
- **Content Security Policy**: Strict CSP prevents code injection
- **Sandboxed Execution**: Vulnerability detection runs in isolated context
- **Regular Updates**: Vulnerability database is updated regularly

## Troubleshooting

### Common Issues

1. **Extension Not Loading**
   - Verify Firefox version (55+ required)
   - Check manifest.json syntax
   - Look for errors in Browser Console (Ctrl+Shift+J)

2. **No Vulnerabilities Detected**
   - Ensure scanning is enabled in settings
   - Check if page uses HTTPS (some CDNs may be blocked)
   - Verify vulnerability database is up to date

3. **Performance Issues**
   - Disable deep scanning if experiencing slowdowns
   - Increase file size limits in settings
   - Check for conflicting extensions

### Debug Mode

Enable debug mode in settings to get detailed logging:
1. Open Settings → Advanced → Enable Debug Mode
2. Open Browser Console (Ctrl+Shift+J)
3. Look for retire.js log messages

### Reporting Issues

1. **GitHub Issues**: https://github.com/RetireJS/retire.js/issues
2. **Include Information**:
   - Firefox version
   - Extension version
   - Steps to reproduce
   - Console error messages

## Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make changes and test thoroughly
4. Submit a pull request

### Code Style

- Use ES6+ features where supported
- Follow Mozilla's WebExtensions guidelines
- Include comprehensive error handling
- Add tests for new functionality

### Testing Requirements

- All new features must include tests
- Existing tests must pass
- Manual testing on multiple Firefox versions
- Performance impact assessment

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgments

- Original retire.js project by Erlend Oftedal
- Mozilla WebExtensions documentation
- Firefox extension development community

## Changelog

### v2.0.0 (Current)
- Complete rewrite using modern WebExtensions API
- Added deep scanning with AST analysis
- Implemented automatic database updates
- Added comprehensive settings panel
- Improved performance and error handling
- Added extensive test suite

### Migration from Legacy Extension
This version replaces the legacy Add-on SDK based Firefox extension with a modern WebExtensions implementation, providing better performance, security, and compatibility with current Firefox versions.