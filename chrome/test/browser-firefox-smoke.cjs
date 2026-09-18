// Firefox's native Marionette protocol, with an isolated disposable profile.
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const http = require("node:http");
const { spawn } = require("node:child_process");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "../..");
const output = path.join(root, "tmp/browser-smoke");
const profile = path.join(output, "firefox-profile-" + Date.now());
fs.mkdirSync(profile, { recursive: true });
fs.writeFileSync(
  path.join(profile, "user.js"),
  'user_pref("marionette.port", 2829);\nuser_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("browser.startup.homepage_override.mstone", "ignore");\n',
);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function main() {
  const server = http.createServer((request, response) => {
    if (request.url === "/jquery-1.12.4.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end(
        '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\nwindow.jQuery={fn:{jquery:"1.12.4"}};',
      );
    } else {
      response.setHeader("Content-Type", "text/html");
      response.end(
        '<!doctype html><title>Retire smoke fixture</title><script src="/jquery-1.12.4.js"></script>',
      );
    }
  });
  await new Promise((resolve) => server.listen(8767, "127.0.0.1", resolve));
  const log = fs.openSync(path.join(output, "firefox.log"), "w");
  const child = spawn(
    "C:/Program Files/Mozilla Firefox/firefox.exe",
    [
      "--headless",
      "--no-remote",
      "--profile",
      profile,
      "--marionette",
      "--remote-allow-system-access",
    ],
    { windowsHide: true, stdio: ["ignore", log, log] },
  );
  let socket;
  try {
    for (let i = 0; i < 100; i++) {
      socket = await new Promise((resolve) => {
        const client = net.connect(2829, "127.0.0.1", () => resolve(client));
        client.once("error", () => {
          client.destroy();
          resolve(null);
        });
      });
      if (socket) break;
      await wait(200);
    }
    if (!socket) throw Error("Firefox Marionette port did not open");
    let sequence = 0,
      buffer = Buffer.alloc(0);
    const pending = new Map();
    socket.on("data", (bytes) => {
      buffer = Buffer.concat([buffer, bytes]);
      while (true) {
        const colon = buffer.indexOf(":");
        if (colon < 0) return;
        const length = Number(buffer.subarray(0, colon).toString());
        if (buffer.length < colon + 1 + length) return;
        const data = JSON.parse(buffer.subarray(colon + 1, colon + 1 + length));
        buffer = buffer.subarray(colon + 1 + length);
        if (!Array.isArray(data)) continue;
        const promise = pending.get(data[1]);
        if (!promise) continue;
        pending.delete(data[1]);
        clearTimeout(promise.timer);
        data[2]
          ? promise.reject(Error(JSON.stringify(data[2])))
          : promise.resolve(data[3]);
      }
    });
    const send = (method, parameters = {}) =>
      new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(Error("Timed out: " + method));
        }, 15000);
        pending.set(id, { resolve, reject, timer });
        const data = JSON.stringify([0, id, method, parameters]);
        socket.write(Buffer.byteLength(data) + ":" + data);
      });
    const session = await send("WebDriver:NewSession", {
      capabilities: { alwaysMatch: {} },
    });
    console.log("Firefox:", session.capabilities.browserVersion);
    console.log(
      "Addon:",
      await send("Addon:Install", {
        path: path.join(root, "dist/firefox"),
        temporary: true,
      }),
    );
    await send("WebDriver:Navigate", { url: "http://127.0.0.1:8767/" });
    await send("Marionette:SetContext", { value: "chrome" });
    const evaluate = (script) =>
      send("WebDriver:ExecuteScript", {
        script,
        args: [],
        newSandbox: false,
        sandbox: "default",
      });
    await evaluate(
      'const {ExtensionParent}=ChromeUtils.importESModule("resource://gre/modules/ExtensionParent.sys.mjs"); const e=WebExtensionPolicy.getByID("jid1-WraQ74BxTHiaUw@jetpack.org").extension; const a=ExtensionParent.apiManager.getAPI("browserAction", e, "addon_parent"); a.openPopup(window,true);',
    );
    await wait(2000);
    const popup = async (script) =>
      (
        await evaluate(
          `const b=[...document.querySelectorAll("browser")].find(x=>x.currentURI?.spec.endsWith("/popup.html"));const a=b.browsingContext.currentWindowGlobal.getActor("MarionetteCommands");return a.executeScript(${JSON.stringify(script)},[],{});`,
        )
      ).value;
    const metrics = await popup(
      'return {width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth,rows:document.querySelector("#rows").textContent,total:Number(document.querySelector("#total").textContent)};',
    );
    assert.equal(metrics.width, 600);
    assert.equal(metrics.height, 600);
    assert.equal(metrics.scrollWidth, 600);
    assert(metrics.rows.includes("jquery"));
    assert(metrics.total > 0);
    console.log("Native popup:", metrics);
    const png = await evaluate(
      'const b=[...document.querySelectorAll("browser")].find(x=>x.currentURI?.spec.endsWith("/popup.html"));return b.browsingContext.currentWindowGlobal.drawSnapshot(new DOMRect(0,0,600,600),1,"rgb(255,255,255)").then(bitmap=>{const c=document.createElementNS("http://www.w3.org/1999/xhtml","canvas");c.width=600;c.height=600;c.getContext("2d").drawImage(bitmap,0,0);return c.toDataURL("image/png").split(",")[1]});',
    );
    fs.writeFileSync(
      path.join(output, "popup-firefox.png"),
      Buffer.from(png.value, "base64"),
    );
    await popup(
      'document.querySelector("#search").value="no-such-library";document.querySelector("#search").dispatchEvent(new Event("input"));',
    );
    assert.equal(
      await popup('return document.querySelectorAll("#rows tr").length;'),
      0,
    );
    assert.equal(
      await popup(
        'return Number(document.querySelector("#total").textContent);',
      ),
      metrics.total,
    );
    await popup(
      'document.querySelector("#search").value="";document.querySelector("#search").dispatchEvent(new Event("input"));document.querySelector("#copy").click();',
    );
    await wait(500);
    assert.match(
      await popup('return document.querySelector("#feedback").textContent;'),
      /URL copied|Press Ctrl/,
    );
    await popup('document.querySelector("#enabled").click();');
    await wait(500);
    assert.equal(
      await popup('return document.querySelector("#state").textContent;'),
      "Scanning disabled",
    );
    console.log(
      "PASS: Firefox real detection, native600×600 popup, search with unfiltered counts, copy/fallback, persistent setting; screenshot in",
      output,
    );
    await send("Marionette:Quit", { flags: ["eForceQuit"] });
  } finally {
    socket?.destroy();
    child.kill();
    fs.closeSync(log);
    server.close();
  }
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
