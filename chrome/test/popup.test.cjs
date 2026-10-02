const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.join(__dirname, "../extension/js/popup.js"),
  "utf8",
);
function context(extra = {}) {
  const sandbox = vm.createContext({
    URL,
    document: { createElement: (tag) => ({ tag }) },
    ...extra,
  });
  vm.runInContext(
    source.slice(0, source.indexOf("for (const [id, setting]")),
    sandbox,
  );
  return sandbox;
}

test("popup keeps resource outcomes distinct and orders actual advisory severities", () => {
  const sandbox = context();
  sandbox.data = {
    resources: [
      {
        url: "https://example.test/unknown.js",
        status: "complete",
        results: [],
      },
      {
        url: "https://example.test/error.js",
        status: "error",
        error: "Fetch failed",
        results: [],
      },
      {
        url: "https://example.test/pending.js",
        status: "scanning",
        results: [],
      },
      {
        url: "https://example.test/a.js",
        status: "complete",
        results: [
          {
            component: "a",
            version: "1",
            vulnerabilities: [{ severity: "low" }],
          },
          {
            component: "z",
            version: "2",
            vulnerabilities: [{ severity: "critical" }],
          },
          { component: "unrated", version: "3", vulnerabilities: [{}] },
        ],
      },
    ],
  };
  const rows = vm.runInContext("libraries(data)", sandbox);
  assert.equal(rows[0].component, "z");
  assert.equal(rows[1].component, "a");
  assert.equal(rows[2].component, "unrated");
  assert.equal(rows.filter((row) => row.unknown).length, 1);
  assert.equal(
    rows.find((row) => row.status === "error").error,
    "Fetch failed",
  );
  assert.equal(rows.find((row) => row.status === "scanning").unknown, false);
  assert.equal(
    vm.runInContext('severity({ severity: "unexpected" })', sandbox),
    "unknown",
  );
  assert.equal(
    vm.runInContext(
      'identifiers({identifiers:{summary:"omit",CVE:["CVE-2020-1234"],githubID:"GHSA-abcd"}}).join(" ")',
      sandbox,
    ),
    "CVE-2020-1234 GHSA-abcd",
  );
  assert.equal(
    sandbox.data.resources[3].results[0].url,
    undefined,
    "UI must not mutate raw export data",
  );
});

test("popup renders untrusted strings as text and permits only HTTP(S) advisory links", () => {
  const sandbox = context();
  for (const address of [
    "javascript:alert(1)",
    "data:text/html,test",
    "file:///tmp/test",
    "/relative",
    "not a URL",
  ]) {
    sandbox.address = address;
    assert.equal(vm.runInContext("safeLink(address)", sandbox), null);
  }
  sandbox.address = "https://example.test/<img>";
  const link = vm.runInContext("safeLink(address)", sandbox);
  assert.equal(link.textContent, sandbox.address);
  assert.equal(link.target, "_blank");
  assert.equal(link.rel, "noopener noreferrer");
  assert.equal(
    vm.runInContext(
      'element("p", "<script>alert(1)</script>").textContent',
      sandbox,
    ),
    "<script>alert(1)</script>",
  );
  assert.equal(source.includes("innerHTML"), false);
});

test("popup messaging supports callback Chrome and promise browser APIs, including errors", async () => {
  const sandbox = context({
    chrome: {
      runtime: {
        sendMessage: (message, done) => done(message),
        lastError: null,
      },
    },
  });
  assert.equal(
    (
      await vm.runInContext(
        'extensionCall("runtime", "sendMessage", {type:"getSnapshot"})',
        sandbox,
      )
    ).type,
    "getSnapshot",
  );
  sandbox.chrome.runtime.lastError = { message: "Disconnected" };
  await assert.rejects(
    vm.runInContext('extensionCall("runtime", "sendMessage", {})', sandbox),
    /Disconnected/,
  );
  sandbox.browser = {
    runtime: { sendMessage: async () => ({ settings: { enabled: false } }) },
  };
  assert.equal(
    (
      await vm.runInContext(
        'extensionCall("runtime", "sendMessage", {})',
        sandbox,
      )
    ).settings.enabled,
    false,
  );
});
