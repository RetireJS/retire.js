// Native Chrome DevTools smoke check; no browser automation dependencies.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { spawn } = require("node:child_process");
const root = path.resolve(__dirname, "../..");
const output = path.join(root, "tmp", "browser-smoke");
fs.mkdirSync(output, { recursive: true });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(check, description, timeout = 20000) {
  const end = Date.now() + timeout;
  let lastError;
  while (Date.now() < end) {
    const value = await check().catch((error) => {
      lastError = error;
      return null;
    });
    if (value) return value;
    await delay(200);
  }
  throw Error(`Timed out: ${description}; ${lastError || "no match"}`);
}
async function connect(url) {
  const socket = new WebSocket(url);
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = reject;
  });
  let sequence = 0;
  const pending = new Map();
  const events = [];
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (!message.id) {
      events.push(message);
      return;
    }
    const callback = pending.get(message.id);
    if (!callback) return;
    pending.delete(message.id);
    message.error
      ? callback.reject(Error(JSON.stringify(message.error)))
      : callback.resolve(message.result);
  };
  return {
    events,
    close: () => socket.close(),
    send(method, params = {}, sessionId) {
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        pending.set(id, { resolve, reject });
        socket.send(
          JSON.stringify({
            id,
            method,
            params,
            ...(sessionId ? { sessionId } : {}),
          }),
        );
      });
    },
  };
}
async function main() {
  const server = http.createServer((request, response) => {
    if (request.url === "/jquery-1.12.4.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end(
        '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\nwindow.jQuery = {fn:{jquery:"1.12.4"}};',
      );
    } else if (request.url === "/function-only.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end(`window['j'+'Query']={fn:{['j'+'query']:'1.12.4'}};`);
    } else if (request.url === "/unknown.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end("window.smokeUnknown = true;");
    } else if (request.url === "/concept.html") {
      response.setHeader("Content-Type", "text/html");
      response.end(fs.readFileSync(path.join(root, "concept.html")));
    } else {
      response.setHeader("Content-Type", "text/html");
      response.end(
        '<!doctype html><title>Retire smoke fixture</title><script src="/jquery-1.12.4.js"></script><script src="/unknown.js"></script><script src="/function-only.js"></script><h1>Retire smoke fixture</h1>',
      );
    }
  });
  await new Promise((resolve) => server.listen(8767, "127.0.0.1", resolve));
  const extension = path.join(root, "dist", process.argv[2] || "chrome");
  const log = fs.openSync(path.join(output, "chrome.log"), "w");
  const child = spawn(
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    [
      "--headless=new",
      "--screen-info={0,0 1280x960}",
      "--force-device-scale-factor=1",
      "--window-size=1280,960",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-gpu",
      "--remote-debugging-port=9237",
      "--remote-allow-origins=http://localhost:9237",
      `--user-data-dir=${path.join(output, "chrome-profile-" + Date.now())}`,
      "--disable-features=DisableLoadExtensionCommandLineSwitch",
      `--load-extension=${extension}`,
      "--enable-unsafe-extension-debugging",
      "about:blank",
    ],
    { windowsHide: true, stdio: ["ignore", log, log] },
  );
  let client;
  try {
    const version = await until(
      async () => (await fetch("http://127.0.0.1:9237/json/version")).json(),
      "Chrome debugging port",
    );
    console.log("Browser:", version.Browser);
    client = await connect(version.webSocketDebuggerUrl);
    let worker = await until(
      async () =>
        (await client.send("Target.getTargets")).targetInfos.find(
          (t) =>
            t.type === "service_worker" &&
            t.url.startsWith("chrome-extension://") &&
            t.url.endsWith("/js/service_worker.js"),
        ),
      "unpacked extension service worker",
      8000,
    ).catch(() => null);
    if (!worker) {
      // Current branded Chrome removes --load-extension; the extension-debugging API is its supported alternative.
      const loaded = await client.send("Extensions.loadUnpacked", {
        path: extension,
      });
      console.log("Loaded extension:", loaded.id);
      worker = await until(
        async () =>
          (await client.send("Target.getTargets")).targetInfos.find(
            (t) =>
              t.type === "service_worker" &&
              t.url.startsWith("chrome-extension://") &&
              t.url.endsWith("/js/service_worker.js"),
          ),
        "extension service worker",
      );
    }
    console.log("Worker:", worker.url);
    const workerSession = (
      await client.send("Target.attachToTarget", {
        targetId: worker.targetId,
        flatten: true,
      })
    ).sessionId;
    await client.send("Runtime.enable", {}, workerSession);
    const evaluate = async (expression, session) => {
      const result = await client.send(
        "Runtime.evaluate",
        { expression, awaitPromise: true, returnByValue: true },
        session,
      );
      if (result.exceptionDetails)
        throw Error(JSON.stringify(result.exceptionDetails));
      return result.result.value;
    };
    const targetId = (
      await client.send("Target.createTarget", {
        url: "http://127.0.0.1:8767/",
      })
    ).targetId;
    await client.send("Target.activateTarget", { targetId });
    await evaluate("chrome.action.openPopup()", workerSession);
    const popupTarget = (
      await until(
        async () =>
          (await client.send("Target.getTargets")).targetInfos.find(
            (t) => t.url === new URL("/popup.html", worker.url).href,
          ),
        "action popup target",
      )
    ).targetId;
    const popupSession = (
      await client.send("Target.attachToTarget", {
        targetId: popupTarget,
        flatten: true,
      })
    ).sessionId;
    await client.send("Runtime.enable", {}, popupSession);
    await client.send("Page.enable", {}, popupSession);

    let lastData;
    const snapshot = await until(async () => {
      const data = await evaluate(
        '(async()=>{const [tab]=await chrome.tabs.query({active:true,currentWindow:true});return await chrome.runtime.sendMessage({type:"getSnapshot",tabId:tab.id,url:tab.url})})()',
        popupSession,
      );
      lastData = data;
      return data?.resources?.some((r) =>
        r.results.some((x) => x.component === "jquery"),
      ) && data.status === "ready"
        ? data
        : null;
    }, "real jQuery detection").catch((error) => {
      console.error("Last snapshot:", JSON.stringify(lastData));
      throw error;
    });
    assert(snapshot.totalVulns > 0);
    const functionOnly = snapshot.resources.find((resource) =>
      resource.url.endsWith("/function-only.js"),
    );
    assert(functionOnly, "function-only fixture was scanned");
    if (process.argv[2] === "chrome-no-func")
      assert.equal(functionOnly.results.length, 0);
    else
      assert(
        functionOnly.results.some(
          (result) =>
            result.component === "jquery" && result.detections.includes("func"),
        ),
        "sandbox function detector identifies the dynamic version",
      );
    console.log(
      "Snapshot:",
      JSON.stringify({
        urlsScanned: snapshot.urlsScanned,
        totalVulns: snapshot.totalVulns,
        resources: snapshot.resources.length,
      }),
    );
    fs.writeFileSync(
      path.join(output, "snapshot.json"),
      JSON.stringify(snapshot, null, 2),
    );
    await until(
      () =>
        evaluate(
          'document.querySelector("#rows")?.textContent.includes("jquery")',
          popupSession,
        ),
      "popup rows",
    );
    assert.equal(
      await evaluate("document.body.offsetWidth", popupSession),
      600,
    );
    assert.equal(
      await evaluate("document.body.offsetHeight", popupSession),
      600,
    );
    console.log(
      "Popup viewport:",
      await evaluate(
        "({width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth,clientWidth:document.documentElement.clientWidth})",
        popupSession,
      ),
    );
    assert.equal(await evaluate("innerWidth", popupSession), 600);
    assert.equal(await evaluate("innerHeight", popupSession), 600);
    assert.equal(
      await evaluate("document.documentElement.scrollWidth", popupSession),
      600,
    );
    assert(
      await evaluate(
        'Number(document.querySelector("#total").textContent)>0',
        popupSession,
      ),
    );
    const screenshot = await client.send(
      "Page.captureScreenshot",
      { format: "png" },
      popupSession,
    );
    fs.writeFileSync(
      path.join(output, `popup-${process.argv[2] || "chrome"}.png`),
      Buffer.from(screenshot.data, "base64"),
    );
    await evaluate('document.querySelector("#copy").click()', popupSession);
    await until(
      () =>
        evaluate(
          '/URL copied|Press Ctrl/.test(document.querySelector("#feedback").textContent)',
          popupSession,
        ),
      "copy URL or manual fallback",
    );
    await evaluate(
      'document.querySelector("#search").value="no-such-library";document.querySelector("#search").dispatchEvent(new Event("input"))',
      popupSession,
    );
    assert.equal(
      await evaluate(
        'document.querySelectorAll("#rows tr").length',
        popupSession,
      ),
      0,
    );
    assert(
      await evaluate(
        'Number(document.querySelector("#total").textContent)>0',
        popupSession,
      ),
    );
    const downloadPath = path.join(output, "downloads-" + Date.now());
    fs.mkdirSync(downloadPath);
    await client.send("Browser.setDownloadBehavior", {
      behavior: "allow",
      downloadPath,
    });
    await evaluate('document.querySelector("#export").click()', popupSession);
    const exported = await until(async () => {
      const file = path.join(downloadPath, "retire-scan.json");
      return fs.existsSync(file)
        ? JSON.parse(fs.readFileSync(file, "utf8"))
        : null;
    }, "full JSON download");
    assert.equal(exported.resources.length, snapshot.resources.length);
    assert.equal(exported.totalVulns, snapshot.totalVulns);
    await evaluate(
      'document.querySelector("#search").value="";document.querySelector("#search").dispatchEvent(new Event("input"));document.querySelector("#unknown").click()',
      popupSession,
    );
    await until(
      () =>
        evaluate(
          'document.querySelector("#rows").textContent.includes("Unidentified script")',
          popupSession,
        ),
      "unknown setting",
    );
    await evaluate('document.querySelector("#enabled").click()', popupSession);
    await until(
      () =>
        evaluate(
          'document.querySelector("#state").textContent==="Scanning disabled"',
          popupSession,
        ),
      "disable setting",
    );
    const errors = client.events.filter(
      (event) => event.method === "Runtime.exceptionThrown",
    );
    assert.equal(errors.length, 0, JSON.stringify(errors));
    await evaluate('document.querySelector("#enabled").click()', popupSession);
    await until(
      () =>
        evaluate(
          'document.querySelector("#enabled").checked && !document.querySelector("#enabled").disabled',
          popupSession,
        ),
      "re-enable setting",
    );
    const fixtureSession = (
      await client.send("Target.attachToTarget", { targetId, flatten: true })
    ).sessionId;
    await client.send(
      "Page.navigate",
      { url: "chrome://settings/" },
      fixtureSession,
    );
    await until(
      () =>
        evaluate(
          'document.querySelector("#state").textContent === "Unsupported page"',
          popupSession,
        ),
      "unsupported page state",
    );
    const conceptTarget = (
      await client.send("Target.createTarget", {
        url: "http://127.0.0.1:8767/concept.html",
      })
    ).targetId;
    const conceptSession = (
      await client.send("Target.attachToTarget", {
        targetId: conceptTarget,
        flatten: true,
      })
    ).sessionId;
    await client.send(
      "Emulation.setDeviceMetricsOverride",
      { width: 800, height: 1000, deviceScaleFactor: 1, mobile: false },
      conceptSession,
    );
    await until(
      () =>
        evaluate('document.querySelector(".console") !== null', conceptSession),
      "concept page",
    );
    const clip = await evaluate(
      '(()=>{const r=document.querySelector(".console").getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,scale:1}})()',
      conceptSession,
    );
    const concept = await client.send(
      "Page.captureScreenshot",
      { format: "png", clip },
      conceptSession,
    );
    fs.writeFileSync(
      path.join(output, "concept.png"),
      Buffer.from(concept.data, "base64"),
    );
    console.log(
      "PASS: real detection, native 600×600 popup, search/counts, copy/fallback, full JSON export, settings, unsupported page, no runtime exceptions; screenshots in",
      output,
    );
  } finally {
    if (client) {
      await client.send("Browser.close").catch(() => {});
      client.close();
    }
    child.kill();
    fs.closeSync(log);
    server.close();
  }
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
