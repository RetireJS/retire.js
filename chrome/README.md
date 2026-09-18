# Browser extensions

## Install without Node.js

Download this repository using **Code → Download ZIP** on GitHub and extract it, or clone it. Complete prebuilt packages are included:

- `dist/chrome`: Chrome 116+, with sandboxed function detection.
- `dist/chrome-no-func`: Chrome 116+, static and AST detection only.
- `dist/firefox`: Firefox 140+, static and AST detection only.

In Chrome, open `chrome://extensions`, enable Developer mode, and **Load unpacked** from the appropriate extracted `dist` directory. For Firefox, see [the Firefox instructions](../firefox/README.md). No Node.js installation or build is needed to load these packages.

## Development

Use Node.js 24 LTS and npm. Run `build_chrome.bat` on Windows or `./build_chrome.sh` on Unix from the repository root. The build compiles the scanner and creates all three packages without relying on symlinks. Reload the extension and test page after rebuilding. Include updated `dist` packages when committing changes to their sources; CI checks that the packages match the build.

The Analyst Console is shared source in `chrome/extension/popup.html`, `popup.css`, and `js/popup.js`. The shared background runtime is `js/runtime.js`. `chrome/build/build.js` bundles that runtime with the scanner and copies the UI and browser-specific manifest into each package. Load the built packages, not the source directories.

Scanning observes new HTTP(S) script requests. Reload an already-open page to scan it. Enabled and Deep scan default to on; settings persist across browser restarts. Disabling scanning retains results. The badge counts unique vulnerable library occurrences (URL, component, version); Total vulns counts distinct advisory occurrences across those libraries. Search and Show unknown do not change totals or exported data. Results are reset on navigation and retained only for the current browser session.

The standard Chrome package executes downloaded JavaScript in an isolated sandbox to detect versions. Use Chrome no-func or Firefox if that behavior is unwanted. Static scanning and AST analysis do not execute downloaded scripts.

## Checks

After compiling Node sources, run `npm test` in `chrome/build` for the extension regression tests. Run `npm run build` there to rebuild the three packages. The repository Node tests and validation tools are unchanged in scope.

Native browser smoke checks are also available from the repository root on Windows with Chrome and Firefox installed in their default locations and Node.js 22 or newer:

```text
node chrome/test/browser-smoke.cjs chrome
node chrome/test/browser-smoke.cjs chrome-no-func
node chrome/test/browser-firefox-smoke.cjs
```

These checks launch hidden headless browsers with isolated profiles, serve local test pages, and save screenshots and test exports under ignored `tmp/browser-smoke/`. Run them sequentially because they share a local fixture port. They do not access your normal browser profiles. CI runs the unit checks and builds on Windows and Ubuntu; native browser checks are separate.
