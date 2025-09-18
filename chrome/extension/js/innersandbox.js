// Retire.js inner sandbox (SAFE ANALYZER)
// This version NEVER executes page scripts.
// It only runs regex/hash extractors on provided script text.

import { repo } from "./retire-chrome.js"; // built repo with extractors

(function () {
  "use strict";
  console.log("inner sandbox (analyzer) loaded");

  // Utility: test filename, URI, filecontent, and hashes
  function analyzeScript(data) {
    const results = [];
    const { url, content } = data;
    if (!url && !content) return results;

    for (const [lib, def] of Object.entries(repo)) {
      const extractors = def.extractors || {};
      let version = null;

      // Filename match
      if (!version && extractors.filename) {
        extractors.filename.forEach((re) => {
          const m = new RegExp(re).exec(url || "");
          if (m && m[1]) version = m[1];
        });
      }

      // URI match
      if (!version && extractors.uri) {
        extractors.uri.forEach((re) => {
          const m = new RegExp(re).exec(url || "");
          if (m && m[1]) version = m[1];
        });
      }

      // Filecontent match
      if (!version && extractors.filecontent && content) {
        extractors.filecontent.forEach((re) => {
          const m = new RegExp(re).exec(content);
          if (m && m[1]) version = m[1];
        });
      }

      // Hash match
      if (!version && extractors.hashes && content) {
        // Compute sha1 of content
        try {
          const enc = new TextEncoder();
          const buf = enc.encode(content);
          crypto.subtle.digest("SHA-1", buf).then((hash) => {
            const hex = Array.from(new Uint8Array(hash))
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");
            if (extractors.hashes[hex]) {
              version = extractors.hashes[hex];
              postResult(lib, version, data);
            }
          });
        } catch (e) {
          console.debug("Hashing failed", e);
        }
      }

      if (version) {
        results.push({ lib, version });
        postResult(lib, version, data);
      }
    }

    return results;
  }

  function postResult(lib, version, original) {
    window.parent.postMessage(
      { component: lib, version, original },
      "*"
    );
  }

  // Main message handler
  window.addEventListener("message", (evt) => {
    try {
      const data = evt.data || {};
      analyzeScript(data);
      evt.source && evt.source.postMessage({ done: true }, "*");
    } catch (err) {
      console.warn("SANDBOX ERROR analyzer", err);
      try {
        evt.source &&
          evt.source.postMessage({ done: true, error: String(err) }, "*");
      } catch {}
    }
  });
})();
