const REPO_URL =
  "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v6-combined.json";
const MAX_AGE = 6 * 60 * 60 * 1000;
const DEFAULTS = { enabled: true, deepScan: true, showUnknown: false };

function mergeResults(results) {
  const merged = new Map();
  for (const result of results) {
    const key = JSON.stringify([result.component, result.version]);
    let item = merged.get(key);
    if (!item) {
      item = { ...result, detections: [], vulnerabilities: [] };
      merged.set(key, item);
    }
    item.detections = [
      ...new Set(
        [
          ...item.detections,
          ...(result.detections || []),
          result.detection,
        ].filter(Boolean),
      ),
    ];
    for (const vulnerability of result.vulnerabilities || []) {
      const identifiers = (v) => {
        const entries = Object.entries(v.identifiers || {});
        const canonical = entries.filter(
          ([key]) => key === "CVE" || key === "githubID",
        );
        const values = canonical.flatMap(([key, ids]) =>
          (Array.isArray(ids) ? ids : [ids]).map((id) => `${key}:${id}`),
        );
        return values.length
          ? values
          : entries
              .filter(([key]) => key !== "summary")
              .flatMap(([key, ids]) =>
                (Array.isArray(ids) ? ids : [ids]).map((id) => `${key}:${id}`),
              );
      };
      const ids = identifiers(vulnerability);
      const existing = item.vulnerabilities.find((v) =>
        ids.length
          ? identifiers(v).some((id) => ids.includes(id))
          : JSON.stringify(v) === JSON.stringify(vulnerability),
      );
      if (!existing) item.vulnerabilities.push({ ...vulnerability });
    }
  }
  return [...merged.values()];
}

function parseRepository(data, retire) {
  const parsed = JSON.parse(
    retire.replaceVersion(
      typeof data === "string" ? data : JSON.stringify(data),
    ),
  );
  if (
    !parsed ||
    !parsed.advisories ||
    typeof parsed.advisories !== "object" ||
    Array.isArray(parsed.advisories)
  )
    throw Error("Invalid advisory repository");
  for (const entry of Object.values(parsed.advisories)) {
    if (!entry || !entry.extractors || !Array.isArray(entry.vulnerabilities))
      throw Error("Invalid repository entry");
    for (const [kind, extractors] of Object.entries(entry.extractors)) {
      if (kind === "hashes") {
        if (
          !extractors ||
          typeof extractors !== "object" ||
          Object.values(extractors).some((v) => typeof v !== "string")
        )
          throw Error("Invalid hash extractors");
      } else {
        if (
          !Array.isArray(extractors) ||
          extractors.some((v) => typeof v !== "string")
        )
          throw Error("Invalid extractors");
        if (["uri", "filename", "filecontent"].includes(kind))
          extractors.forEach((value) => new RegExp(value));
      }
    }
    for (const vulnerability of entry.vulnerabilities) {
      if (
        !vulnerability ||
        typeof vulnerability.below !== "string" ||
        !Array.isArray(vulnerability.info)
      )
        throw Error("Invalid advisory");
    }
  }
  parsed.backdoored ||= {};
  for (const advisories of Object.values(parsed.backdoored)) {
    if (!Array.isArray(advisories)) throw Error("Invalid backdoor repository");
    for (const advisory of advisories) {
      if (!Array.isArray(advisory.extractors))
        throw Error("Invalid backdoor extractors");
      advisory.extractors.forEach((value) => new RegExp(value));
    }
  }
  return parsed;
}

function startRuntime(api, engine, options = {}) {
  const download = options.fetch || globalThis.fetch.bind(globalThis);
  let settings = { ...DEFAULTS };
  let tabs = {};
  let repository = parseRepository(engine.repo, engine.retire);
  let updatedAt = 0;
  let attemptedAt = 0;
  let repositoryError = null;
  let refresh;
  let writes = Promise.resolve();
  let offscreen;
  let settingsGeneration = 0;
  const requests = new Map();
  const hasher = {
    sha1: (content) => engine.sha1().update(content).digest("hex"),
  };
  const reportError = (error) => console.warn("Retire.js:", error);

  async function text(url) {
    const response = await download(url, {
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw Error(`HTTP ${response.status} downloading ${url}`);
    return response.text();
  }

  async function refreshRepository() {
    if (refresh) return refresh;
    if (Date.now() - updatedAt < MAX_AGE || Date.now() - attemptedAt < 60000)
      return;
    attemptedAt = Date.now();
    refresh = (async () => {
      try {
        const next = parseRepository(await text(REPO_URL), engine.retire);
        repository = next;
        updatedAt = Date.now();
        repositoryError = null;
        await api.storage.local.set({ repository: { data: next, updatedAt } });
      } catch (error) {
        repositoryError = `Repository update failed; using saved or bundled data. ${error.message}`;
      }
    })().finally(() => {
      refresh = null;
    });
    return refresh;
  }

  function persist() {
    const data = structuredClone(tabs);
    const pending = [...requests.entries()];
    // Serialize writes so an older scan cannot overwrite newer navigation state.
    writes = writes
      .catch(reportError)
      .then(() => api.storage.session.set({ tabs: data, requests: pending }));
    return writes;
  }

  function newTab(url = "", timeStamp = Date.now()) {
    return {
      url,
      startedAt: timeStamp,
      generation: crypto.randomUUID(),
      resources: {},
    };
  }

  function snapshot(tabId, url) {
    const tab = tabs[tabId];
    const resources = Object.values(tab?.resources || {});
    const results = resources.flatMap((resource) => resource.results);
    const tabUrl = url || tab?.url || "";
    return {
      settings: { ...settings },
      tabId,
      url: tabUrl,
      scannedAt: tab?.scannedAt || null,
      status:
        tabUrl && !/^https?:\/\//.test(tabUrl)
          ? "unsupported"
          : resources.some((r) => r.status === "scanning")
            ? "loading"
            : "ready",
      repositoryError,
      urlsScanned: resources.length,
      totalVulns: results.reduce(
        (count, result) => count + (result.vulnerabilities?.length || 0),
        0,
      ),
      vulnerableCount: results.filter(
        (result) => result.vulnerabilities?.length,
      ).length,
      resources,
    };
  }

  async function badge(tabId) {
    if (tabId < 0) return;
    const count = snapshot(tabId).vulnerableCount;
    try {
      await api.action.setBadgeText({
        tabId: Number(tabId),
        text: settings.enabled && count ? String(count) : "",
      });
    } catch {
      /* The tab may have closed while a scan completed. */
    }
  }

  async function icon() {
    await api.action.setIcon({
      path: api.runtime.getURL(
        settings.enabled ? "icons/icon48.png" : "icons/icon_bw48.png",
      ),
    });
  }

  const ready = (async () => {
    const [local, session] = await Promise.all([
      api.storage.local.get(["settings", "repository"]),
      api.storage.session.get(["tabs", "requests"]),
    ]);
    for (const key of Object.keys(DEFAULTS))
      if (typeof local.settings?.[key] === "boolean")
        settings[key] = local.settings[key];
    tabs = session.tabs || {};
    if (local.repository) {
      try {
        repository = parseRepository(local.repository.data, engine.retire);
        updatedAt = local.repository.updatedAt || 0;
      } catch {
        repositoryError = "Saved repository is invalid; using bundled data.";
      }
    }
    const openTabs = await api.tabs.query({});
    const openIds = new Set(openTabs.map((tab) => String(tab.id)));
    for (const id of Object.keys(tabs)) if (!openIds.has(id)) delete tabs[id];
    for (const [id, request] of session.requests || [])
      if (openIds.has(String(request.tabId))) requests.set(id, request);
    for (const open of openTabs)
      if (tabs[open.id]?.url && open.url && tabs[open.id].url !== open.url)
        tabs[open.id] = newTab(open.url);
    for (const tab of Object.values(tabs))
      for (const resource of Object.values(tab.resources)) {
        if (resource.status === "scanning") {
          resource.status = "error";
          resource.error = "Scan interrupted. Reload the page to scan again.";
        }
      }
    await persist();
    await api.action.setBadgeBackgroundColor({ color: "#c13832" });
    await icon();
    await Promise.all(Object.keys(tabs).map(badge));
  })();
  ready.catch(reportError);

  async function sandbox(content, url, repo) {
    if (!options.sandbox) return [];
    if (!offscreen) {
      offscreen = (async () => {
        if (!(await api.offscreen.hasDocument()))
          await api.offscreen.createDocument({
            url: "background.html",
            reasons: ["IFRAME_SCRIPTING"],
            justification:
              "Detect library versions in isolated script sandboxes",
          });
      })().finally(() => {
        offscreen = null;
      });
    }
    await offscreen;
    const repoFuncs = Object.fromEntries(
      Object.entries(repo)
        .filter(([, value]) => value.extractors.func)
        .map(([name, value]) => [name, value.extractors.func]),
    );
    const response = await api.runtime.sendMessage({
      target: "offscreen",
      type: "sandbox",
      content,
      url,
      repoFuncs,
    });
    if (!response || response.error)
      throw Error(response?.error || "Sandbox did not respond");
    return response.results
      .filter(
        (result) =>
          typeof result.version === "string" &&
          result.version.length <= 100 &&
          Object.hasOwn(repoFuncs, result.component),
      )
      .flatMap((result) =>
        engine.retire
          .check(result.component, result.version, repo)
          .map((item) => ({ ...item, detection: "func" })),
      );
  }

  async function scan(details) {
    await ready;
    const request = requests.get(details.requestId);
    requests.delete(details.requestId);
    if (
      !request ||
      !settings.enabled ||
      details.tabId < 0 ||
      details.type !== "script" ||
      !/^https?:\/\//.test(details.url)
    ) {
      await persist();
      return;
    }
    const tab = (tabs[details.tabId] ||= newTab("", details.timeStamp));
    if (
      request.generation !== tab.generation ||
      details.timeStamp < tab.startedAt
    ) {
      await persist();
      return;
    }
    const settingEpoch = settingsGeneration;
    const resource = { url: details.url, status: "scanning", results: [] };
    tab.resources[details.url] = resource;
    const current = () =>
      settings.enabled &&
      settingsGeneration === settingEpoch &&
      tabs[details.tabId] === tab &&
      tab.resources[details.url] === resource;
    await persist();
    try {
      await refreshRepository();
      if (!current()) return;
      const scanRepo = repository;
      const advisories = scanRepo.advisories;
      const results = [];
      for (const [component, entries] of Object.entries(scanRepo.backdoored)) {
        const matching = entries.filter((entry) =>
          entry.extractors.some((pattern) =>
            new RegExp(pattern).test(details.url),
          ),
        );
        if (matching.length)
          results.push({
            component,
            version: "-",
            detection: "url",
            vulnerabilities: matching.map((v) => ({
              ...v,
              identifiers: { ...v.identifiers, summary: v.summary },
            })),
          });
      }
      results.push(...engine.retire.scanUri(details.url, advisories));
      if (!results.length)
        results.push(
          ...engine.retire.scanFileName(
            new URL(details.url).pathname.split("/").pop(),
            advisories,
          ),
        );
      if (!results.length) {
        const content = await text(details.url);
        if (!current()) return;
        results.push(
          ...engine.retire.scanFileContent(content, advisories, hasher),
        );
        if (settings.deepScan) {
          try {
            results.push(
              ...engine
                .deepScan(content, advisories)
                .map((result) => ({ ...result, detection: "ast" })),
            );
          } catch (error) {
            resource.error = `Deep scan failed: ${error.message}`;
          }
        }
        const license = content.match(
          /^\/\*! For license information please see ([^\r\n]+?) \*\//,
        );
        if (license) {
          const licenseUrl = new URL(license[1], details.url);
          if (
            /^https?:$/.test(licenseUrl.protocol) &&
            licenseUrl.origin === new URL(details.url).origin
          ) {
            try {
              results.push(
                ...engine.retire.scanFileContent(
                  await text(licenseUrl.href),
                  advisories,
                  hasher,
                ),
              );
            } catch (error) {
              resource.error = `License file scan failed: ${error.message}`;
            }
          }
        }
        if (current() && options.sandbox) {
          try {
            results.push(...(await sandbox(content, details.url, advisories)));
          } catch (error) {
            resource.error = `Function detection failed: ${error.message}`;
          }
        }
      }
      if (!current()) return;
      resource.results = mergeResults(results);
      resource.status = resource.error ? "error" : "complete";
    } catch (error) {
      if (!current()) return;
      resource.status = "error";
      resource.error = error.message;
    }
    if (current()) {
      tab.scannedAt = new Date().toISOString();
      await persist();
      await badge(details.tabId);
    }
  }

  api.webRequest.onBeforeRequest.addListener(
    async (details) => {
      await ready;
      if (!settings.enabled || details.tabId < 0 || details.type !== "script")
        return;
      const tab = (tabs[details.tabId] ||= newTab("", details.timeStamp));
      requests.set(details.requestId, {
        generation: tab.generation,
        tabId: details.tabId,
      });
      await persist();
    },
    { urls: ["http://*/*", "https://*/*"], types: ["script"] },
  );
  api.webRequest.onCompleted.addListener(
    (details) => scan(details).catch(reportError),
    { urls: ["http://*/*", "https://*/*"], types: ["script"] },
  );
  api.webRequest.onErrorOccurred.addListener(
    async (details) => {
      await ready;
      requests.delete(details.requestId);
      await persist();
    },
    { urls: ["http://*/*", "https://*/*"], types: ["script"] },
  );
  api.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    await ready;
    tabs[details.tabId] = newTab(details.url, details.timeStamp);
    await persist();
    await badge(details.tabId);
  });
  api.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    await ready;
    const tab = (tabs[details.tabId] ||= newTab(
      details.url,
      details.timeStamp,
    ));
    tab.url = details.url;
    await persist();
  });
  api.tabs.onRemoved.addListener(async (tabId) => {
    await ready;
    delete tabs[tabId];
    for (const [id, request] of requests)
      if (request.tabId === tabId) requests.delete(id);
    await persist();
  });
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (
      sender.id !== api.runtime.id ||
      sender.tab ||
      message.target === "offscreen"
    )
      return false;
    if (!["getSnapshot", "setSettings"].includes(message.type)) return false;
    (async () => {
      await ready;
      if (message.type === "getSnapshot")
        return snapshot(message.tabId, message.url);
      let changed = false;
      for (const key of Object.keys(DEFAULTS))
        if (
          typeof message.settings?.[key] === "boolean" &&
          settings[key] !== message.settings[key]
        ) {
          settings[key] = message.settings[key];
          if (key !== "showUnknown") changed = true;
        }
      if (changed) {
        settingsGeneration++;
        requests.clear();
        for (const tab of Object.values(tabs))
          for (const resource of Object.values(tab.resources))
            if (resource.status === "scanning") {
              resource.status = "error";
              resource.error =
                "Scan settings changed. Reload the page to scan again.";
            }
        await persist();
      }
      await api.storage.local.set({ settings });
      await icon();
      await Promise.all(Object.keys(tabs).map(badge));
      return { settings: { ...settings } };
    })().then(sendResponse, (error) => sendResponse({ error: error.message }));
    return true;
  });
  return { ready };
}

module.exports = { startRuntime, mergeResults, parseRepository };
