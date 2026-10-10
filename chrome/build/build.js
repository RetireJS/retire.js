const fs = require("node:fs");
const path = require("node:path");
const esbuild = require("esbuild");

const root = path.resolve(__dirname, "../..");
const source = path.join(__dirname, "extension");
async function build() {
  for (const [directory, manifest, sandbox] of [
    ["chrome/extension", "chrome/build/extension/manifest.json", true],
    ["chrome/extension-no-func", "chrome/build/extension-no-func/manifest.json", false],
    ["dist/firefox", "firefox/manifest.json", false],
  ]) {
    const destination = path.join(root, directory);
    fs.mkdirSync(path.join(destination, "js"), { recursive: true });
    fs.copyFileSync(
      path.join(root, manifest),
      path.join(destination, "manifest.json"),
    );
    for (const file of [
      "popup.html",
      "popup.css",
      "js/popup.js",
      ...(sandbox
        ? [
            "background.html",
            "inner-sandbox.html",
            "js/background.js",
            "js/innersandbox.js",
          ]
        : []),
    ]) {
      fs.copyFileSync(path.join(source, file), path.join(destination, file));
    }
    fs.cpSync(path.join(source, "icons"), path.join(destination, "icons"), {
      recursive: true,
    });
    await esbuild.build({
      entryPoints: [path.join(source, "js/service_worker.js")],
      outfile: path.join(destination, "js/service_worker.js"),
      bundle: true,
      platform: "browser",
      format: "iife",
      target: ["chrome116", "firefox140"],
      define: { FUNCTION_SCANNING: String(sandbox) },
      logLevel: "info",
    });
    console.log(`Built ${directory}`);
  }
}
build().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
