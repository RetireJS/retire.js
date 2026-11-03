const { test } = require("node:test");
const assert = require("node:assert/strict");
const { startRuntime, mergeResults } = require("../build/extension/js/runtime.js");
const retire = require("../../node/lib/retire.js");

test("distinct Bootstrap CVEs sharing one issue are retained across repeated detections", () => {
  const data = require("../../repository/jsrepository-v6-combined.json");
  const results = retire.check("bootstrap", "4.0.0", data.advisories);
  assert.equal(results[0].vulnerabilities.length, 4);
  assert.equal(
    mergeResults([...results, ...results])[0].vulnerabilities.length,
    4,
  );
});

const repo = {
  advisories: {
    alpha: {
      extractors: {},
      vulnerabilities: [
        {
          below: "2.0",
          severity: "high",
          identifiers: { CVE: ["CVE-2026-1000"] },
          info: [],
        },
      ],
    },
    beta: { extractors: {}, vulnerabilities: [] },
  },
  backdoored: {},
};
const event = () => ({
  listeners: [],
  addListener(fn) {
    this.listeners.push(fn);
  },
  async emit(...args) {
    return Promise.all(this.listeners.map((fn) => fn(...args)));
  },
});
function harness({
  local = {},
  bundledRepo = repo,
  openTabs = [{ id: 1, url: "https://example.test/" }],
  fetch = async () => ({ ok: true, text: async () => "first" }),
  deepScan,
  pageScripts = [],
} = {}) {
  const storage = (data) => ({
    async get() {
      return structuredClone(data);
    },
    async set(values) {
      Object.assign(data, structuredClone(values));
    },
  });
  const badges = [];
  const injected = [];
  const api = {
    runtime: {
      id: "test",
      onMessage: event(),
      getURL: (path) => `chrome-extension://test/${path}`,
    },
    webNavigation: { onBeforeNavigate: event(), onCommitted: event() },
    webRequest: {
      onBeforeRequest: event(),
      onCompleted: event(),
      onErrorOccurred: event(),
    },
    tabs: {
      onActivated: event(),
      onRemoved: event(),
      async query() {
        return openTabs;
      },
      async get(id) {
        return openTabs.find((tab) => tab.id === id);
      },
    },
    scripting: {
      async executeScript(injection) {
        injected.push(injection.target.tabId);
        if (pageScripts instanceof Error) throw pageScripts;
        return [{ result: pageScripts }];
      },
    },
    storage: {
      local: storage({
        repository: { data: repo, updatedAt: Date.now() },
        ...local,
      }),
    },
    action: {
      async setBadgeText(value) {
        badges.push(value);
      },
      async setBadgeBackgroundColor() {},
      async setIcon({ path }) {
        assert.match(path, /^chrome-extension:\/\/test\/icons\//, "worker icons need extension-root URLs");
      },
    },
  };
  const engine = {
    retire,
    repo: bundledRepo,
    sha1: () => ({
      update() {
        return this;
      },
      digest() {
        return "";
      },
    }),
    deepScan:
      deepScan ||
      (() =>
        retire
          .check("alpha", "1.0", repo.advisories)
          .concat(retire.check("beta", "1.0", repo.advisories))),
  };
  const runtime = startRuntime(api, engine, { fetch, discoverDelay: 0 });
  const message = (data) =>
    new Promise((resolve) =>
      api.runtime.onMessage.listeners[0](data, { id: "test" }, resolve),
    );
  const scan = async (url = "https://example.test/app.js", requestId = "1") => {
    const details = {
      url,
      tabId: 1,
      type: "script",
      requestId,
      timeStamp: Date.now(),
    };
    await api.webRequest.onBeforeRequest.emit(details);
    await api.webRequest.onCompleted.emit(details);
  };
  return { api, ready: runtime.ready, message, scan, badges, injected };
}

test("keeps all AST matches, merges repeated findings, and derives counts", async () => {
  const h = harness();
  await h.ready;
  await h.scan();
  await h.scan();
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.equal(snapshot.resources[0].results.length, 2);
  assert.equal(snapshot.urlsScanned, 1);
  assert.equal(snapshot.totalVulns, 1);
  assert.equal(snapshot.vulnerableCount, 1);
});

test("disabled scanning persists and does not download scripts", async () => {
  let downloads = 0;
  const h = harness({
    fetch: async () => {
      downloads++;
      throw Error("unexpected download");
    },
  });
  await h.ready;
  await h.message({ type: "setSettings", settings: { enabled: false } });
  await h.scan();
  assert.equal(downloads, 0);
  assert.equal(
    (await h.message({ type: "getSnapshot", tabId: 1 })).settings.enabled,
    false,
  );
});

test("changed content at the same URL is scanned again", async () => {
  let content = "1.0";
  const h = harness({
    fetch: async () => ({ ok: true, text: async () => content }),
    deepScan: (text) => retire.check("alpha", text, repo.advisories),
  });
  await h.ready;
  await h.scan();
  content = "3.0";
  await h.scan();
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.equal(snapshot.resources[0].results[0].version, "3.0");
  assert.equal(snapshot.totalVulns, 0);
});

test("refresh discards results and rescans observed scripts without a reload", async () => {
  let content = "1.0";
  let downloads = 0;
  const h = harness({
    fetch: async () => {
      downloads++;
      return { ok: true, text: async () => content };
    },
    deepScan: (text) => retire.check("alpha", text, repo.advisories),
    pageScripts: new Error("The extensions gallery cannot be scripted."),
  });
  await h.ready;
  await h.scan();
  content = "3.0";
  assert.deepEqual(await h.message({ type: "rescan", tabId: 1 }), {
    rescanned: 1,
  });
  let snapshot;
  do {
    await new Promise((resolve) => setImmediate(resolve));
    snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  } while (snapshot.resources[0]?.status !== "complete");
  assert.equal(downloads, 2);
  assert.equal(snapshot.resources.length, 1);
  assert.equal(snapshot.resources[0].results[0].version, "3.0");
  assert.equal(snapshot.totalVulns, 0);
});

const settle = async (h) => {
  let snapshot;
  do {
    await new Promise((resolve) => setTimeout(resolve));
    snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  } while (snapshot.status !== "ready");
  return snapshot;
};

test("switching to a tab loaded before the worker started scans its page scripts", async () => {
  const h = harness({ pageScripts: ["https://example.test/app.js", "", "data:,x"] });
  await h.ready;
  await h.api.tabs.onActivated.emit({ tabId: 1 });
  const snapshot = await settle(h);
  assert.deepEqual(h.injected, [1]);
  assert.deepEqual(snapshot.resources.map((r) => r.url), ["https://example.test/app.js"]);
  assert.equal(snapshot.totalVulns, 1);
});

test("opening the popup completes a tab first seen through a late script request", async () => {
  const h = harness({ pageScripts: ["https://example.test/app.js"] });
  await h.ready;
  await h.scan("https://example.test/late.js");
  await h.message({ type: "getSnapshot", tabId: 1, url: "https://example.test/" });
  const snapshot = await settle(h);
  assert.deepEqual(
    snapshot.resources.map((r) => r.url).sort(),
    ["https://example.test/app.js", "https://example.test/late.js"],
  );
  await h.api.tabs.onActivated.emit({ tabId: 1 });
  assert.deepEqual(h.injected, [1], "a discovered tab is not read again");
});

test("tabs watched from navigation are not read again on activation", async () => {
  const h = harness({ pageScripts: ["https://example.test/app.js"] });
  await h.ready;
  await h.api.webNavigation.onBeforeNavigate.emit({
    tabId: 1,
    frameId: 0,
    url: "https://example.test/",
    timeStamp: Date.now(),
  });
  await h.api.tabs.onActivated.emit({ tabId: 1 });
  await h.message({ type: "getSnapshot", tabId: 1, url: "https://example.test/" });
  assert.deepEqual(h.injected, []);
});

test("the active tab is discovered when the worker starts", async () => {
  const h = harness({
    openTabs: [{ id: 1, active: true, url: "https://example.test/" }],
    pageScripts: ["https://example.test/app.js"],
  });
  await h.ready;
  const snapshot = await settle(h);
  assert.deepEqual(h.injected, [1]);
  assert.deepEqual(snapshot.resources.map((r) => r.url), ["https://example.test/app.js"]);
});

test("navigation during the discover wait is not overwritten", async () => {
  const h = harness({ pageScripts: ["https://example.test/app.js"] });
  await h.ready;
  const pending = h.api.tabs.onActivated.emit({ tabId: 1 });
  for (let i = 0; i < 10; i++) await null; // let discover() start its wait
  await h.api.webNavigation.onBeforeNavigate.emit({
    tabId: 1,
    frameId: 0,
    url: "https://example.test/next",
    timeStamp: Date.now(),
  });
  await pending;
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(h.injected, []);
});

test("refresh keeps scripts still downloading", async () => {
  const h = harness();
  await h.ready;
  const details = {
    requestId: "late",
    tabId: 1,
    url: "https://example.test/chunk.js",
    type: "script",
    timeStamp: Date.now(),
  };
  await h.api.webRequest.onBeforeRequest.emit(details);
  await h.message({ type: "rescan", tabId: 1 });
  await h.api.webRequest.onCompleted.emit({ ...details, timeStamp: Date.now() });
  const snapshot = await settle(h);
  assert.deepEqual(snapshot.resources.map((r) => r.url), ["https://example.test/chunk.js"]);
});

test("late results cannot leak into the next navigation", async () => {
  let finish;
  const h = harness({
    fetch: () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  });
  await h.ready;
  const pending = h.scan();
  while (!finish) await new Promise((resolve) => setImmediate(resolve));
  await h.api.webNavigation.onBeforeNavigate.emit({
    tabId: 1,
    frameId: 0,
    url: "https://new.test/",
    timeStamp: Date.now(),
  });
  finish({ ok: true, text: async () => "first" });
  await pending;
  assert.equal(
    (await h.message({ type: "getSnapshot", tabId: 1 })).resources.length,
    0,
  );
});

test("background restart discards results, clears badges and registers listeners immediately", async () => {
  const first = harness();
  await first.ready;
  await first.scan();
  const second = harness();
  assert.equal(second.api.webRequest.onCompleted.listeners.length, 1);
  await second.ready;
  assert.ok(second.badges.some((b) => b.tabId === 1 && b.text === ""));
  assert.equal(
    (await second.message({ type: "getSnapshot", tabId: 1 })).totalVulns,
    0,
  );
  await second.scan("https://example.test/second.js");
  assert.equal(
    (await second.message({ type: "getSnapshot", tabId: 1 })).urlsScanned,
    1,
  );
});

test("failed scripts are reported individually while later scans succeed", async () => {
  const h = harness({
    fetch: async (url) => {
      if (url.includes("bad.js")) throw Error("offline");
      return { ok: true, text: async () => "first" };
    },
  });
  await h.ready;
  await h.scan("https://example.test/bad.js");
  await h.scan();
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.equal(
    snapshot.resources.find((r) => r.url.endsWith("bad.js")).status,
    "error",
  );
  assert.equal(snapshot.totalVulns, 1);
});

test("old requests are discarded across same-URL navigation and worker restart", async () => {
  const first = harness();
  await first.ready;
  await first.api.webNavigation.onBeforeNavigate.emit({
    tabId: 1,
    frameId: 0,
    url: "https://example.test/",
    timeStamp: Date.now(),
  });
  await first.scan();
  const details = {
    url: "https://example.test/old.js",
    tabId: 1,
    type: "script",
    requestId: "old",
    timeStamp: Date.now(),
  };
  await first.api.webRequest.onBeforeRequest.emit(details);
  await first.api.webNavigation.onBeforeNavigate.emit({
    tabId: 1,
    frameId: 0,
    url: "https://example.test/",
    timeStamp: Date.now(),
  });
  assert.equal(
    (await first.message({ type: "getSnapshot", tabId: 1 })).totalVulns,
    0,
  );
  const second = harness();
  await second.ready;
  await second.api.webRequest.onCompleted.emit({
    ...details,
    timeStamp: Date.now() + 1,
  });
  assert.equal(
    (await second.message({ type: "getSnapshot", tabId: 1 })).resources.length,
    0,
  );
});

test("invalid remote repository retains cached detectors and exposes update error", async () => {
  const h = harness({
    local: { repository: { data: repo, updatedAt: 1 } },
    fetch: async (url) => ({
      ok: true,
      text: async () =>
        url.includes("githubusercontent") ? "{broken" : "first",
    }),
  });
  await h.ready;
  await h.scan();
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.equal(snapshot.totalVulns, 1);
  assert.match(snapshot.repositoryError, /using saved or bundled/);
});

test("a fresh offline install detects vulnerabilities with the bundled repository", async () => {
  const downloads = [];
  const h = harness({
    local: { repository: undefined },
    bundledRepo: require("../../repository/jsrepository-v6-combined.json"),
    fetch: async (url) => {
      downloads.push(url);
      throw Error("offline");
    },
  });
  await h.ready;
  await h.scan("https://example.test/jquery-1.12.4.js");
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.equal(downloads.length, 1);
  assert.match(downloads[0], /githubusercontent/);
  assert.equal(snapshot.resources[0].status, "complete");
  assert.equal(snapshot.resources[0].results[0].component, "jquery");
  assert.ok(snapshot.totalVulns > 0);
  assert.match(snapshot.repositoryError, /using saved or bundled data.*offline/);
});

test("repository refresh updates the repository passed to AST detection", async () => {
  const next = structuredClone(repo);
  next.advisories.alpha.vulnerabilities = [];
  const h = harness({
    local: { repository: { data: repo, updatedAt: 1 } },
    fetch: async (url) => ({
      ok: true,
      text: async () =>
        url.includes("githubusercontent") ? JSON.stringify(next) : "first",
    }),
    deepScan: (_, current) => retire.check("alpha", "1.0", current),
  });
  await h.ready;
  await h.scan();
  assert.equal(
    (await h.message({ type: "getSnapshot", tabId: 1 })).totalVulns,
    0,
  );
});

test("real AST engine returns multiple libraries from one bundle", async () => {
  const data = structuredClone(repo);
  data.advisories.alpha.extractors.ast = [
    "//VariableDeclarator[/:id/:name == 'alphaVersion']/:init/:value",
  ];
  data.advisories.beta.extractors.ast = [
    "//VariableDeclarator[/:id/:name == 'betaVersion']/:init/:value",
  ];
  const h = harness({
    local: { repository: { data, updatedAt: Date.now() } },
    fetch: async () => ({
      ok: true,
      text: async () => 'const alphaVersion="1.0"; const betaVersion="1.0";',
    }),
    deepScan: require("../../node/lib/deepscan.js").deepScan,
  });
  await h.ready;
  await h.scan();
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.deepEqual(
    snapshot.resources[0].results.map((r) => r.component),
    ["alpha", "beta"],
  );
  assert.equal(snapshot.totalVulns, 1);
});

test("disabling during a download prevents late results even after re-enabling", async () => {
  let finish;
  const h = harness({
    fetch: () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  });
  await h.ready;
  const pending = h.scan();
  while (!finish) await new Promise((resolve) => setImmediate(resolve));
  await h.message({ type: "setSettings", settings: { enabled: false } });
  await h.message({ type: "setSettings", settings: { enabled: true } });
  finish({ ok: true, text: async () => "first" });
  await pending;
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.equal(snapshot.totalVulns, 0);
  assert.equal(snapshot.resources[0].status, "error");
});

test("settings restore and closed tabs lose their results", async () => {
  const h = harness({
    local: { settings: { enabled: false, deepScan: false, showUnknown: true } },
  });
  await h.ready;
  const snapshot = await h.message({ type: "getSnapshot", tabId: 1 });
  assert.deepEqual(snapshot.settings, {
    enabled: false,
    deepScan: false,
    showUnknown: true,
  });
  await h.message({ type: "setSettings", settings: { enabled: true } });
  await h.scan();
  await h.api.tabs.onRemoved.emit(1);
  assert.equal((await h.message({ type: "getSnapshot", tabId: 1 })).urlsScanned, 0);
});

test("closing a tab during a scan discards late results and pending requests", async () => {
  let finish;
  const h = harness({
    fetch: () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  });
  await h.ready;
  const pending = h.scan();
  while (!finish) await new Promise((resolve) => setImmediate(resolve));
  const details = {
    url: "https://example.test/late.js",
    tabId: 1,
    type: "script",
    requestId: "late",
    timeStamp: Date.now(),
  };
  await h.api.webRequest.onBeforeRequest.emit(details);
  await h.api.tabs.onRemoved.emit(1);
  finish({ ok: true, text: async () => "first" });
  await pending;
  await h.api.webRequest.onCompleted.emit(details);
  assert.equal(
    (await h.message({ type: "getSnapshot", tabId: 1 })).urlsScanned,
    0,
  );

  await h.api.webNavigation.onBeforeNavigate.emit({
    tabId: 2,
    frameId: 0,
    url: "https://new.test/",
    timeStamp: Date.now(),
  });
  assert.equal(
    (await h.message({ type: "getSnapshot", tabId: 2 })).totalVulns,
    0,
  );
});

test("iframe navigation preserves the current top-level page results", async () => {
  const h = harness();
  await h.ready;
  await h.scan();
  const navigation = { tabId: 1, frameId: 2, url: "https://frame.test/", timeStamp: Date.now() };
  await h.api.webNavigation.onBeforeNavigate.emit(navigation);
  await h.api.webNavigation.onCommitted.emit(navigation);
  assert.equal(
    (await h.message({ type: "getSnapshot", tabId: 1 })).totalVulns,
    1,
  );
});
