const { test } = require("node:test");
const assert = require("node:assert/strict");
const { startRuntime, mergeResults } = require("../extension/js/runtime.js");
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
  session = {},
  local = {},
  fetch = async () => ({ ok: true, text: async () => "first" }),
  deepScan,
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
      onRemoved: event(),
      async query() {
        return [{ id: 1, url: "https://example.test/" }];
      },
    },
    storage: {
      local: storage({
        repository: { data: repo, updatedAt: Date.now() },
        ...local,
      }),
      session: storage(session),
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
    repo,
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
  const runtime = startRuntime(api, engine, { fetch });
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
  return { api, ready: runtime.ready, message, scan, badges, session };
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

test("background restart restores results and registers request listeners immediately", async () => {
  const session = {};
  const first = harness({ session });
  await first.ready;
  await first.scan();
  const second = harness({ session });
  assert.equal(second.api.webRequest.onCompleted.listeners.length, 1);
  await second.ready;
  assert.equal(
    (await second.message({ type: "getSnapshot", tabId: 1 })).totalVulns,
    1,
  );
  await second.scan("https://example.test/second.js");
  assert.equal(
    (await second.message({ type: "getSnapshot", tabId: 1 })).urlsScanned,
    2,
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

test("request ownership survives a worker restart across navigation", async () => {
  const session = {};
  const first = harness({ session });
  await first.ready;
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
  const second = harness({ session });
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

test("settings restore and closed tabs are removed from session data", async () => {
  const session = {};
  const h = harness({
    session,
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
  assert.deepEqual(session.tabs, {});
  assert.deepEqual(session.requests, []);
});
