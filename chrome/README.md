# Development

To use the development version:

1. Clone the repo: `git clone https://github.com/RetireJS/retire.js`
2. Install the requirements: npm - [https://docs.npmjs.com/downloading-and-installing-node-js-and-npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
3. Run `./build_chrome.sh` (Linux) or `./build_chrome.bat` (Windows) from the root of the repo
4. Open [chrome://extensions/](chrome://extensions/)
5. Check "Developer mode"
6. Click "Load unpacked" at the top left, and select the `chrome/extension` or `chrome/extension-no-func` folder inside the repo
7. Use and develop

To test the reporting, you can visit the demo page at [https://erlend.oftedal.no/blog/retire/](https://erlend.oftedal.no/blog/retire/)

## SECURITY NOTICE: Difference between extension and extension-no-func

The default extension loads the downloaded scripts in an iframe and then tries to invoke JavaScript functions from the downloaded repo (like `jQuery.fn.version`) in a sandbox to try to
detect certain libraries. If this is not acceptable security-wise, you can use extension-no-func, which does not invoke those functions.

### Development

Be wary when updating the files, as files not related to no-func, are symlinked between the two versions to avoid having to update in both places.
