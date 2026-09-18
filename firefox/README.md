# Retire.js for Firefox

The current extension is a Manifest V3 WebExtension for Firefox 140 or newer. It shares the Analyst Console and static/AST scanner with Chrome; it does not execute downloaded scripts.

1. Run `build_chrome.bat` (Windows) or `./build_chrome.sh` (Unix) from the repository root.
2. Open `about:debugging#/runtime/this-firefox`.
3. Choose **Load Temporary Add-on**, then select `dist/firefox/manifest.json`.
4. Allow site access when prompted, open an HTTP(S) page, and reload it to scan its scripts.
5. Open the Retire.js toolbar popup to inspect libraries, search advisories, or export JSON.

Temporary installation lasts until Firefox exits. Store signing and publication are not part of this development build. The existing extension ID is preserved in `firefox/manifest.json`.

The files under `firefox/lib`, `firefox/data`, and `firefox/test` belong to the archived Add-on SDK implementation and are not packaged or executed. The modern build uses `chrome/extension` as shared source and `firefox/manifest.json` for Firefox configuration. See [shared development and test instructions](../chrome/README.md).
