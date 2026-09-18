"use strict";

const $ = (id) => document.getElementById(id);
const severityScore = { critical: 4, high: 3, medium: 2, low: 1 };
const detectionNames = {
  ast: "AST",
  uri: "URI",
  filename: "file name",
  filecontent: "file content",
};
let snapshot = null;
let selected = null;
let rowsSignature = "";
let detailSignature = "";
let refreshing = false;
let settingWrites = 0;
let revision = 0;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

// Chromium exposes callbacks; Firefox's browser namespace exposes promises.
function extensionCall(target, method, argument) {
  if (typeof browser !== "undefined") return browser[target][method](argument);
  return new Promise((resolve, reject) => {
    const result = chrome[target][method](argument, (value) => {
      const error = chrome.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve(value);
    });
    if (result && typeof result.then === "function")
      result.then(resolve, reject);
  });
}

function severity(vulnerability) {
  const value = String(vulnerability.severity || "").toLowerCase();
  return Object.hasOwn(severityScore, value) ? value : "unknown";
}

function identifiers(vulnerability) {
  return Object.entries(vulnerability.identifiers || {})
    .filter(([key]) => key !== "summary")
    .flatMap(([, value]) => (Array.isArray(value) ? value : [value]))
    .filter((value) => typeof value === "string" || typeof value === "number")
    .map(String);
}

function libraries(data) {
  return (data.resources || [])
    .flatMap((resource) => {
      const results = resource.results || [];
      if (!results.length) {
        return [
          {
            component:
              resource.status === "error"
                ? "Scan failed"
                : resource.status === "scanning"
                  ? "Scanning script…"
                  : "Unidentified script",
            version: "—",
            url: resource.url,
            status: resource.status,
            error: resource.error,
            unknown: resource.status === "complete",
            vulnerabilities: [],
            key: JSON.stringify([resource.url, resource.status]),
          },
        ];
      }
      return results.map((result) => ({
        ...result,
        url: resource.url,
        status: resource.status,
        error: resource.error,
        vulnerabilities: result.vulnerabilities || [],
        key: JSON.stringify([resource.url, result.component, result.version]),
      }));
    })
    .sort(
      (a, b) =>
        rank(b) - rank(a) ||
        String(a.component).localeCompare(String(b.component)) ||
        String(a.version).localeCompare(String(b.version)) ||
        a.url.localeCompare(b.url),
    );
}

function rank(library) {
  if (library.vulnerabilities.length)
    return Math.max(
      0.5,
      ...library.vulnerabilities.map((v) => severityScore[severity(v)] || 0),
    );
  return library.unknown ? -1 : 0;
}

function badge(library) {
  if (library.vulnerabilities.length) {
    const highest = [...library.vulnerabilities].sort(
      (a, b) =>
        (severityScore[severity(b)] || 0) - (severityScore[severity(a)] || 0),
    )[0];
    const value = severity(highest);
    return element(
      "span",
      value === "unknown"
        ? "Unrated finding"
        : value[0].toUpperCase() + value.slice(1),
      `badge ${value}`,
    );
  }
  return element(
    "span",
    library.status === "error"
      ? "Scan error"
      : library.status === "scanning"
        ? "Scanning"
        : library.unknown
          ? "Unknown"
          : "No known findings",
    "badge neutral",
  );
}

function safeLink(url, text) {
  try {
    const parsed = new URL(url);
    if (!["https:", "http:"].includes(parsed.protocol)) return null;
    const link = element("a", text || url);
    link.href = parsed.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    return link;
  } catch {
    return null;
  }
}

function renderDetails(library) {
  const signature = JSON.stringify(library || null);
  if (signature === detailSignature) return;
  const sameSelection = $("details").dataset.key === library?.key;
  const scroll = sameSelection ? $("details").scrollTop : 0;
  const focusedId = $("details").contains(document.activeElement)
    ? document.activeElement.id
    : null;
  detailSignature = signature;
  $("details").dataset.key = library?.key || "";
  $("details").replaceChildren();
  if (!library) {
    $("details").append(
      element("p", "Select a library to view details.", "placeholder"),
    );
    return;
  }
  const heading = element("div", undefined, "detail-head");
  heading.append(
    element("h2", library.component),
    element("span", library.version, "mono"),
    badge(library),
  );
  const urlrow = element("div", undefined, "urlrow");
  const url = element("input");
  url.id = "url";
  url.readOnly = true;
  url.value = library.url;
  url.setAttribute("aria-label", "Detected file URL");
  const copy = element("button", "Copy URL", "copy");
  copy.id = "copy";
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(library.url);
      $("feedback").textContent = "URL copied.";
    } catch {
      url.focus();
      url.select();
      $("feedback").textContent =
        "Press Ctrl+C / Cmd+C to copy the selected URL.";
    }
  };
  urlrow.append(url, copy);
  $("details").append(heading, urlrow);
  const detections =
    library.detections || (library.detection ? [library.detection] : []);
  if (detections.length)
    $("details").append(
      element(
        "p",
        `Detected by ${detections.map((d) => detectionNames[d] || d).join(", ")}.`,
        "detection",
      ),
    );
  if (library.status === "error")
    $("details").append(
      element(
        "p",
        library.error || "This script could not be scanned.",
        "placeholder",
      ),
    );
  else if (!library.vulnerabilities.length)
    $("details").append(
      element(
        "p",
        library.status === "scanning"
          ? "This script is still being scanned."
          : library.unknown
            ? "Library and version could not be identified."
            : "No matching advisory. This is not a security guarantee.",
        "placeholder",
      ),
    );
  [...library.vulnerabilities]
    .sort(
      (a, b) =>
        (severityScore[severity(b)] || 0) - (severityScore[severity(a)] || 0),
    )
    .forEach((vulnerability) => {
      const finding = element("article", undefined, "finding");
      const level = severity(vulnerability);
      finding.append(
        element(
          "span",
          `${level[0].toUpperCase() + level.slice(1)} severity`,
          `badge ${level}`,
        ),
      );
      const ids = identifiers(vulnerability);
      finding.append(
        element(
          "h3",
          vulnerability.identifiers?.summary || ids.join(" · ") || "Advisory",
        ),
      );
      if (ids.length) finding.append(element("p", ids.join(" · "), "mono"));
      if (vulnerability.details)
        finding.append(element("p", vulnerability.details));
      if (vulnerability.atOrAbove || vulnerability.below)
        finding.append(
          element(
            "p",
            `Affected versions: ${vulnerability.atOrAbove ? `≥ ${vulnerability.atOrAbove}` : ""}${vulnerability.atOrAbove && vulnerability.below ? ", " : ""}${vulnerability.below ? `< ${vulnerability.below}` : ""}`,
          ),
        );
      const links = new Set([].concat(vulnerability.info || []));
      ids.forEach((id) => {
        if (/^CVE-\d{4}-\d+$/i.test(id))
          links.add(
            `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
          );
        if (/^GHSA-[a-z0-9-]+$/i.test(id))
          links.add(`https://github.com/advisories/${encodeURIComponent(id)}`);
      });
      links.forEach((address) => {
        const link = safeLink(address);
        if (link) finding.append(link);
      });
      $("details").append(finding);
    });
  if (sameSelection && focusedId) $(focusedId)?.focus({ preventScroll: true });
  $("details").scrollTop = scroll;
}

function render() {
  if (!snapshot) return;
  const settings = snapshot.settings;
  $("enabled").checked = settings.enabled;
  $("deep").checked = settings.deepScan;
  $("unknown").checked = settings.showUnknown;
  $("mode").textContent = settings.deepScan ? "Deep scan" : "Standard scan";
  $("scanned").textContent = snapshot.urlsScanned || 0;
  $("total").textContent = snapshot.totalVulns || 0;
  $("state").textContent = !settings.enabled
    ? "Scanning disabled"
    : snapshot.status === "unsupported"
      ? "Unsupported page"
      : snapshot.repositoryError
        ? "Using saved data"
        : snapshot.status === "loading"
          ? "Scanning…"
          : "Enabled";
  $("state").classList.toggle(
    "off",
    !settings.enabled || snapshot.status === "unsupported",
  );
  try {
    $("domain").textContent = new URL(snapshot.url).hostname || snapshot.url;
  } catch {
    $("domain").textContent = snapshot.url || "Current tab";
  }
  $("domain").title = snapshot.url || "";
  const query = $("search").value.trim().toLowerCase();
  const list = libraries(snapshot).filter(
    (library) =>
      (!library.unknown || settings.showUnknown) &&
      [
        library.component,
        library.version,
        library.url,
        ...library.vulnerabilities.flatMap(identifiers),
      ]
        .join(" ")
        .toLowerCase()
        .includes(query),
  );
  if (!list.some((library) => library.key === selected))
    selected = list[0]?.key || null;
  $("count").textContent = `${list.length} shown`;
  $("empty").hidden = list.length !== 0;
  $("empty").textContent =
    snapshot.status === "unsupported"
      ? "Scanning is available on HTTP and HTTPS pages."
      : !settings.enabled
        ? "Scanning is disabled. Existing results are retained."
        : snapshot.repositoryError
          ? snapshot.repositoryError
          : snapshot.status === "loading"
            ? "Waiting for scan results…"
            : query
              ? "No matching libraries."
              : "No identified libraries. Enable Show unknown to include unidentified scripts.";
  const signature = JSON.stringify([list, selected]);
  if (signature !== rowsSignature) {
    rowsSignature = signature;
    const focusedKey = $("rows").contains(document.activeElement)
      ? document.activeElement.dataset.key
      : null;
    const scroll = $("rows").parentElement.parentElement.scrollTop;
    const fragment = document.createDocumentFragment();
    list.forEach((library) => {
      const row = element(
        "tr",
        undefined,
        library.key === selected ? "selected" : "",
      );
      const name = element("td");
      const button = element("button", library.component);
      button.dataset.key = library.key;
      button.title = library.url;
      button.setAttribute("aria-pressed", String(library.key === selected));
      button.setAttribute("aria-controls", "details");
      button.onclick = () => {
        selected = library.key;
        render();
      };
      button.onkeydown = (event) => {
        const index = list.indexOf(library);
        const next =
          event.key === "ArrowDown"
            ? Math.min(index + 1, list.length - 1)
            : event.key === "ArrowUp"
              ? Math.max(index - 1, 0)
              : event.key === "Home"
                ? 0
                : event.key === "End"
                  ? list.length - 1
                  : null;
        if (next === null) return;
        event.preventDefault();
        selected = list[next].key;
        render();
        [...$("rows").querySelectorAll("button")]
          .find((b) => b.dataset.key === selected)
          ?.focus();
      };
      name.append(button);
      const level = element("td");
      level.append(badge(library));
      row.append(
        name,
        element("td", library.version || "Unknown", "mono"),
        level,
      );
      fragment.append(row);
    });
    $("rows").replaceChildren(fragment);
    if (focusedKey) {
      const button = [...$("rows").querySelectorAll("button")].find(
        (b) => b.dataset.key === focusedKey,
      );
      (button || $("search")).focus({ preventScroll: true });
    }
    $("rows").parentElement.parentElement.scrollTop = scroll;
  }
  renderDetails(list.find((library) => library.key === selected));
  $("export").disabled = false;
}

async function refresh() {
  if (refreshing || settingWrites) return;
  refreshing = true;
  const requestRevision = revision;
  try {
    const tabs = await extensionCall("tabs", "query", {
      active: true,
      currentWindow: true,
    });
    const tab = tabs[0];
    const data = await extensionCall("runtime", "sendMessage", {
      type: "getSnapshot",
      tabId: tab?.id,
      url: tab?.url,
    });
    if (requestRevision !== revision) return;
    if (!data || !data.settings) throw new Error("No scan snapshot received.");
    const repositoryChanged =
      data.repositoryError !== (snapshot?.repositoryError || null);
    snapshot = data;
    if (repositoryChanged)
      $("feedback").textContent = data.repositoryError || "Repository updated.";
    render();
  } catch (error) {
    $("state").textContent = "Unavailable";
    $("feedback").textContent = `Could not load scan results: ${error.message}`;
    if (!snapshot)
      $("empty").textContent = "Scan results are unavailable. Retrying…";
  } finally {
    refreshing = false;
  }
}

for (const [id, setting] of [
  ["enabled", "enabled"],
  ["deep", "deepScan"],
  ["unknown", "showUnknown"],
]) {
  $(id).onchange = async () => {
    const value = $(id).checked;
    settingWrites++;
    revision++;
    $(id).disabled = true;
    try {
      const result = await extensionCall("runtime", "sendMessage", {
        type: "setSettings",
        settings: { [setting]: value },
      });
      if (!result?.settings) throw new Error("Setting was not saved.");
      if (snapshot) {
        snapshot.settings = result.settings;
        render();
      }
      $("feedback").textContent =
        `${id === "enabled" ? "Scanning" : id === "deep" ? "Deep scan" : "Show unknown"} ${value ? "enabled" : "disabled"}.`;
    } catch (error) {
      $(id).checked = snapshot?.settings[setting] ?? !value;
      $("feedback").textContent = `Could not save setting: ${error.message}`;
    } finally {
      $(id).disabled = false;
      settingWrites--;
      refresh();
    }
  };
}
$("search").oninput = render;
$("export").onclick = () => {
  if (!snapshot) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(snapshot, null, 2)], { type: "application/json" }),
  );
  const link = element("a");
  link.href = url;
  link.download = "retire-scan.json";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  $("feedback").textContent = "Full scan data exported.";
};
refresh();
setInterval(refresh, 1000);
