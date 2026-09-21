const fs = require("node:fs");
const path = require("node:path");
const esbuild = require("esbuild");

const root = path.resolve(__dirname, "../..");
const source = path.join(root, "chrome/extension");
async function build() {
  for (const [name, manifest, sandbox] of [
    ["chrome", "chrome/extension/manifest.json", true],
    ["chrome-no-func", "chrome/extension-no-func/manifest.json", false],
    ["firefox", "firefox/manifest.json", false],
  ]) {
    const destination = path.join(root, "dist", name);
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
    console.log(`Built dist/${name}`);
  }
}
build().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
