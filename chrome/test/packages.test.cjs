const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

for (const directory of ["chrome/extension", "chrome/extension-no-func", "dist/firefox"]) {
  test(`${directory} contains a complete unpacked extension`, () => {
    const root = path.resolve(__dirname, "../..", directory);
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
    const files = [
      manifest.action.default_popup,
      ...Object.values(manifest.icons),
      ...(manifest.background.scripts || [manifest.background.service_worker]),
      ...(manifest.sandbox?.pages || []),
      ...(manifest.permissions.includes("offscreen") ? ["background.html"] : []),
    ];
    for (const file of files) {
      const location = path.join(root, file);
      assert.ok(fs.statSync(location).isFile(), `${directory}/${file}`);
      if (file.endsWith(".html")) {
        const html = fs.readFileSync(location, "utf8");
        for (const [, resource] of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
          assert.ok(fs.statSync(path.resolve(path.dirname(location), resource)).isFile(), resource);
        }
      }
    }
  });
}
