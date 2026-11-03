"use strict";

const $ = (id) => document.getElementById(id);
const severityScore = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const detectionNames = {
  ast: "code analysis (AST)",
  uri: "URL",
  url: "URL",
  filename: "file name",
  filecontent: "file content",
  func: "running the script",
};
const SVG = "http://www.w3.org/2000/svg";
const icons = {
  alert: ["M8 4v4.6", "M8 11.4v.3"],
  check: ["m4 8.4 2.6 2.5L12 5.2"],
  question: ["M6 6.1a2 2 0 1 1 2.8 1.8c-.6.3-.8.7-.8 1.3v.3", "M8 11.8v.2"],
  cross: ["m4.8 4.8 6.4 6.4M11.2 4.8l-6.4 6.4"],
  chevron: ["m6 3.5 4.5 4.5L6 12.5"],
  back: ["M10.5 3 5.5 8l5 5"],
  external: ["M6 3.5h6.5V10M12.5 3.5 4 12"],
  shield: ["M8 1.8 3 3.7v4c0 3 2.1 5.4 5 6.5 2.9-1.1 5-3.5 5-6.5v-4Z", "m5.7 8 1.6 1.6 3-3.2"],
};
let snapshot = null;
let selected = null;
let pushed = false;
let rowsSignature = "";
let pressing = false;
let detailSignature = "";
let refreshing = false;
let settingWrites = 0;
let revision = 0;
let feedbackTimer = 0;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function icon(name, className) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  if (className) svg.setAttribute("class", className);
  for (const d of icons[name]) {
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
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
  if (value === "none") return "info";
  return Object.hasOwn(severityScore, value) ? value : "unknown";
}

function severityCounts(vulnerabilities) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const vulnerability of vulnerabilities) counts[severity(vulnerability)]++;
  return counts;
}

function severityLabel(level) {
  return level === "unknown" ? "Unrated" : level[0].toUpperCase() + level.slice(1);
}

function plural(count, one, many) {
  return `${count} ${count === 1 ? one : many}`;
}

function severityBadges(library) {
  if (!library.vulnerabilities.length) return badge(library);
  const group = element("span", undefined, "severity-badges");
  for (const [level, count] of Object.entries(severityCounts(library.vulnerabilities))) {
    if (!count) continue;
    const label = severityLabel(level);
    const pill = element("span", `${count} ${label[0]}`, `badge ${level}`);
    pill.title = `${count} ${label}`;
    pill.setAttribute("aria-label", pill.title);
    group.append(pill);
  }
  return group;
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

function highest(library) {
  return [...library.vulnerabilities]
    .map(severity)
    .sort((a, b) => (severityScore[b] ?? -1) - (severityScore[a] ?? -1))[0];
}

// Placeholder rows from libraries() have no component match, so they are named after their file.
function kind(library) {
  if (library.vulnerabilities.length) return "vulnerable";
  if (library.status === "error" && library.version === "—") return "error";
  if (library.status === "scanning" && library.version === "—") return "scanning";
  return library.unknown ? "unknown" : "clean";
}

function displayName(library) {
  if (kind(library) === "vulnerable" || kind(library) === "clean")
    return String(library.component);
  return fileName(library.url);
}

function fileName(url) {
  try {
    const parsed = new URL(url);
    return parsed.pathname.split("/").filter(Boolean).pop() || parsed.hostname;
  } catch {
    return url;
  }
}

function hostName(url) {
  try {
    return new URL(url).hostname || url;
  } catch {
    return url;
  }
}

// withFile tells apart rows that share a name: a library found in two bundles, or two scripts with one file name.
function rowDetail(library, withFile) {
  const version = library.version || "Unknown version";
  const file = withFile ? ` · ${fileName(library.url)}` : "";
  switch (kind(library)) {
    case "vulnerable":
      return `${version} · ${plural(library.vulnerabilities.length, "advisory", "advisories")}${file}`;
    case "clean":
      // An identified library whose deep or function scan failed may hide other libraries in the same file.
      return `${version} · ${library.status === "error" ? "Scan incomplete" : "No known findings"}${file}`;
    default:
      return `${library.component}${withFile ? ` · ${hostName(library.url)}` : ""}`;
  }
}

function badge(library) {
  if (library.vulnerabilities.length) {
    const value = highest(library);
    return element(
      "span",
      value === "unknown" ? "Unrated finding" : severityLabel(value),
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

function glyph(library, large) {
  const type = kind(library);
  const tone =
    type === "vulnerable" ? highest(library) : type === "clean" ? "clean" : "neutral";
  const node = element("span", undefined, `glyph ${tone}${large ? " large" : ""}`);
  if (type === "scanning") {
    const spinner = element("span", undefined, "spinner");
    // Lock the phase to the page clock so rows rebuilt by polling do not restart the spin.
    spinner.style.animationDelay = `${-performance.now()}ms`;
    node.append(spinner);
  } else
    node.append(
      icon(
        { vulnerable: "alert", clean: "check", unknown: "question", error: "cross" }[type],
      ),
    );
  return node;
}

// Orders versions like 1.2.10 > 1.2.9 and 3.0.0 > 3.0.0-rc.1.
function compareVersions(a, b) {
  const [mainA, preA] = String(a).split(/-(.*)/);
  const [mainB, preB] = String(b).split(/-(.*)/);
  const x = mainA.split(".");
  const y = mainB.split(".");
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const difference = String(x[i] ?? "0").localeCompare(String(y[i] ?? "0"), "en", {
      numeric: true,
    });
    if (difference) return difference;
  }
  if (preA === preB) return 0;
  if (preA === undefined) return 1;
  if (preB === undefined) return -1;
  return preA.localeCompare(preB, "en", { numeric: true });
}

// "999.0.0" is the repository's marker for "no fixed version yet".
function affectedRange(vulnerability) {
  const { atOrAbove, below } = vulnerability;
  const open = !below || compareVersions(below, "999.0.0") >= 0;
  if (atOrAbove && open) return `Affects ${atOrAbove} and later`;
  if (atOrAbove) return `Affects ${atOrAbove} to below ${below}`;
  if (open) return "Affects all versions";
  return `Affects versions below ${below}`;
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

function linkLabel(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.hostname.replace(/^www\./, "")}${parsed.pathname === "/" ? "" : parsed.pathname}`;
  } catch {
    return url;
  }
}

function feedback(message) {
  $("feedback").textContent = message;
  $("feedback").classList.add("show");
  clearTimeout(feedbackTimer);
  feedbackTimer = setTimeout(() => $("feedback").classList.remove("show"), 2600);
}

function group(title, ...children) {
  const fragment = document.createDocumentFragment();
  if (title) fragment.append(element("h3", title, "section-title"));
  const box = element("div", undefined, "group");
  box.append(...children);
  fragment.append(box);
  return fragment;
}

function line(label, value) {
  const row = element("div", undefined, "line");
  row.append(element("span", label), value);
  return row;
}

function finding(vulnerability) {
  const article = element("article", undefined, "finding");
  const level = severity(vulnerability);
  const top = element("div", undefined, "finding-top");
  top.append(
    element(
      "span",
      level === "unknown" ? "Unrated" : `${severityLabel(level)}`,
      `badge ${level}`,
    ),
    element("span", affectedRange(vulnerability)),
  );
  const ids = identifiers(vulnerability);
  article.append(
    top,
    element(
      "h3",
      vulnerability.identifiers?.summary || ids.join(" · ") || "Advisory",
    ),
  );
  if (ids.length && vulnerability.identifiers?.summary)
    article.append(element("p", ids.join(" · "), "mono"));
  if (vulnerability.details) article.append(element("p", vulnerability.details));
  const links = new Set([].concat(vulnerability.info || []));
  ids.forEach((id) => {
    if (/^CVE-\d{4}-\d+$/i.test(id))
      links.add(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`);
    if (/^GHSA-[a-z0-9-]+$/i.test(id))
      links.add(`https://github.com/advisories/${encodeURIComponent(id)}`);
  });
  const list = element("div", undefined, "links");
  links.forEach((address) => {
    const link = safeLink(address);
    if (!link) return;
    link.title = address;
    link.replaceChildren(element("span", linkLabel(address)), icon("external"));
    list.append(link);
  });
  if (list.childElementCount) article.append(list);
  return article;
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
  if (!library) return;

  const nav = element("header", undefined, "nav");
  const back = element("button", undefined, "back");
  back.id = "back";
  back.type = "button";
  back.append(icon("back"), "Libraries");
  back.onclick = () => closeLibrary();
  nav.append(back, element("span", displayName(library), "nav-title"));

  const content = element("div", undefined, "content");
  const head = element("div", undefined, "detail-head");
  const name = element("div");
  name.append(
    element("h2", displayName(library)),
    ["vulnerable", "clean"].includes(kind(library))
      ? element("p", library.version || "Unknown version", "mono")
      : element("p", library.component),
  );
  head.append(glyph(library, true), name);
  content.append(head);

  const vulnerabilities = [...library.vulnerabilities].sort(
    (a, b) =>
      (severityScore[severity(b)] ?? -1) - (severityScore[severity(a)] ?? -1),
  );
  if (vulnerabilities.length) {
    const pills = element("div", undefined, "pills");
    for (const [level, count] of Object.entries(severityCounts(vulnerabilities)))
      if (count) pills.append(element("span", `${count} ${severityLabel(level)}`, `badge ${level}`));
    content.append(pills);
  } else {
    content.append(
      element(
        "p",
        kind(library) === "error"
          ? library.error || "This script could not be scanned."
          : kind(library) === "scanning"
            ? "This script is still being scanned."
            : library.unknown
              ? "Retire.js could not match this script to a known library."
              : "No matching advisory. This is not a security guarantee.",
        "lead",
      ),
    );
  }

  const url = element("span", library.url, "mono");
  url.id = "url";
  const lines = [line("URL", url)];
  const detections =
    library.detections || (library.detection ? [library.detection] : []);
  if (detections.length)
    lines.push(
      line(
        "Detected by",
        element("span", detections.map((d) => detectionNames[d] || d).join(", ")),
      ),
    );
  if (library.status === "error" && library.error && library.version !== "—")
    lines.push(line("Scan error", element("span", library.error)));
  const copy = element("button", "Copy URL", "action");
  copy.id = "copy";
  copy.type = "button";
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(library.url);
      feedback("URL copied.");
    } catch {
      const range = document.createRange();
      range.selectNodeContents(url);
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      feedback("Press Ctrl+C / Cmd+C to copy the selected URL.");
    }
  };
  const copyLine = element("div", undefined, "line");
  copyLine.append(copy);
  lines.push(copyLine);
  content.append(group("Source", ...lines));

  if (vulnerabilities.length) {
    content.append(element("h3", "Advisories", "section-title"));
    vulnerabilities.forEach((vulnerability) => {
      const box = element("div", undefined, "group");
      box.append(finding(vulnerability));
      content.append(box);
    });
  }
  content.append(
    element("p", "Version matches do not confirm that this page is exploitable.", "footnote"),
  );
  $("details").append(nav, content);
  if (sameSelection && focusedId) $(focusedId)?.focus({ preventScroll: true });
  $("details").scrollTop = scroll;
}

function emptyState(settings, query) {
  const [title, text] =
    snapshot.status === "unsupported"
      ? ["Nothing to scan here", "Scanning is available on HTTP and HTTPS pages."]
      : !settings.enabled
        ? ["Scanning is disabled", "Existing results are retained."]
        : snapshot.repositoryError
          ? ["Using saved data", snapshot.repositoryError]
          : snapshot.status === "loading"
            ? ["Waiting for scan results…", "Libraries appear here as scripts load."]
            : query
              ? ["No matching libraries", "Try a library name, version, URL or advisory ID."]
              : [
                  "No identified libraries",
                  "Turn on Show unidentified scripts in Options to list every script.",
                ];
  const box = element("div", undefined, "group empty");
  box.id = "empty";
  box.append(element("strong", title), element("p", text));
  return box;
}

function rowButton(library, withFile) {
  const button = element("button", undefined, "row");
  button.type = "button";
  button.dataset.key = library.key;
  button.title = library.url;
  const text = element("span", undefined, "row-text");
  text.append(
    element("span", displayName(library), "row-name"),
    element("span", rowDetail(library, withFile), "row-detail"),
  );
  button.append(glyph(library), text);
  const counts = Object.entries(severityCounts(library.vulnerabilities))
    .filter(([, count]) => count)
    .map(([level, count]) => `${count} ${severityLabel(level)}`);
  if (library.vulnerabilities.length || (library.status === "error" && library.version !== "—"))
    button.append(severityBadges(library));
  button.append(icon("chevron", "chevron"));
  button.setAttribute(
    "aria-label",
    [displayName(library), rowDetail(library, withFile), ...counts].join(", "),
  );
  button.onclick = () => openLibrary(library.key);
  return button;
}

function renderRows(list, settings, query) {
  const signature = JSON.stringify([
    list,
    settings.enabled,
    snapshot.status,
    snapshot.repositoryError || null,
    query,
  ]);
  if (signature === rowsSignature) return;
  // Rebuilding mid-press would move the click off the row; the next render applies the update.
  if (pressing) return;
  rowsSignature = signature;
  const focusedKey = $("rows").contains(document.activeElement)
    ? document.activeElement.dataset.key
    : null;
  const sections = [
    ["Vulnerable", (l) => kind(l) === "vulnerable"],
    ["No known findings", (l) => kind(l) === "clean"],
    ["Scanning", (l) => kind(l) === "scanning"],
    ["Other scripts", (l) => kind(l) === "unknown" || kind(l) === "error"],
  ];
  const names = list.map(displayName);
  const shared = new Set(names.filter((name, index) => names.indexOf(name) !== index));
  const fragment = document.createDocumentFragment();
  if (!list.length) fragment.append(emptyState(settings, query));
  for (const [title, test] of sections) {
    const items = list.filter(test);
    if (!items.length) continue;
    const rows = element("ul", undefined, "rows");
    for (const library of items) {
      const item = element("li");
      item.append(rowButton(library, shared.has(displayName(library))));
      rows.append(item);
    }
    const section = element("section");
    section.className = "sections";
    section.setAttribute("aria-label", title);
    section.append(group(title, rows));
    fragment.append(section);
  }
  $("rows").replaceChildren(fragment);
  if (focusedKey)
    ([...$("rows").querySelectorAll(".row")].find((b) => b.dataset.key === focusedKey) ||
      $("search")
    ).focus({ preventScroll: true });
}

function renderSummary(allLibraries, status) {
  const vulnerabilities = allLibraries.flatMap((library) => library.vulnerabilities);
  const counts = severityCounts(vulnerabilities);
  $("severity-summary").replaceChildren();
  $("severity-bar").replaceChildren();
  for (const [level, count] of Object.entries(counts)) {
    if (level === "unknown" && !count) continue;
    const item = element("span", undefined, `${level}${count ? "" : " zero"}`);
    item.append(element("i"), element("strong", count), ` ${severityLabel(level)}`);
    item.dataset.severity = level;
    $("severity-summary").append(item);
    if (count) {
      const segment = element("span", undefined, level);
      segment.style.flex = count;
      $("severity-bar").append(segment);
    }
  }
  const vulnerable = allLibraries.filter((library) => library.vulnerabilities.length).length;
  $("headline").replaceChildren(
    status === "unsupported"
      ? "Nothing to scan on this page"
      : vulnerabilities.length
        ? `${plural(vulnerabilities.length, "advisory", "advisories")} in ${plural(vulnerable, "library", "libraries")}`
        : status === "loading"
          ? "Looking for libraries…"
          : allLibraries.some((library) => kind(library) === "clean")
            ? "No known vulnerabilities"
            : "No libraries identified",
  );
  if (!vulnerabilities.length && status !== "loading" && status !== "unsupported" &&
    allLibraries.some((library) => kind(library) === "clean"))
    $("headline").prepend(icon("shield"));
  $("severity-bar").hidden = !vulnerabilities.length;
}

function render() {
  if (!snapshot) return;
  const settings = snapshot.settings;
  $("enabled").checked = settings.enabled;
  $("deep").checked = settings.deepScan;
  $("unknown").checked = settings.showUnknown;
  $("scanned").textContent = `${plural(snapshot.urlsScanned || 0, "script", "scripts")} scanned`;
  const allLibraries = libraries(snapshot);
  renderSummary(allLibraries, snapshot.status);
  const [state, tone] = !settings.enabled
    ? ["Scanning disabled", "paused"]
    : snapshot.status === "unsupported"
      ? ["Unsupported page", "off"]
      : snapshot.repositoryError
        ? ["Using saved data", "warning"]
        : snapshot.status === "loading"
          ? ["Scanning…", "busy"]
          : ["Active", ""];
  $("state").textContent = state;
  $("state-chip").className = `chip ${tone}`;
  // Matches the toolbar icon, which runtime.js turns gray while scanning is disabled.
  const brandIcon = settings.enabled ? "icons/icon48.png" : "icons/icon_bw48.png";
  if ($("brand-icon").getAttribute("src") !== brandIcon) $("brand-icon").setAttribute("src", brandIcon);
  try {
    $("domain").textContent = new URL(snapshot.url).hostname || snapshot.url;
  } catch {
    $("domain").textContent = snapshot.url || "Current tab";
  }
  $("domain").title = snapshot.url || "";
  $("rescan").disabled = !settings.enabled || snapshot.status === "unsupported";
  $("rescan").classList.toggle("busy", settings.enabled && snapshot.status === "loading");
  const banner = !settings.enabled
    ? "Scanning is disabled. Existing results are retained."
    : snapshot.repositoryError || "";
  $("banner").hidden = !banner;
  $("banner-text").textContent = banner;
  $("resume").hidden = settings.enabled;

  const query = $("search").value.trim().toLowerCase();
  const list = allLibraries.filter(
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
  renderRows(list, settings, query);
  // A row's key changes when its scan finishes; keep the same script open. Keys start with the URL.
  const current =
    allLibraries.find((library) => library.key === selected) ||
    (pushed && selected && allLibraries.find((library) => library.url === JSON.parse(selected)[0]));
  if (current) {
    selected = current.key;
    renderDetails(current);
  } else if (pushed) closeLibrary();
  $("export").disabled = false;
}

function openLibrary(key) {
  selected = key;
  render();
  if (!$("details").childElementCount) return;
  pushed = true;
  document.body.classList.add("pushed");
  $("details").scrollTop = 0;
  $("back").focus({ preventScroll: true });
}

function closeLibrary() {
  if (!pushed) return;
  pushed = false;
  document.body.classList.remove("pushed");
  const row = [...$("rows").querySelectorAll(".row")].find((b) => b.dataset.key === selected);
  (row || $("search")).focus({ preventScroll: true });
}

function setSheet(open) {
  document.body.classList.toggle("sheet-open", open);
  $("stack").inert = open;
  $("options").setAttribute("aria-expanded", String(open));
  (open ? $("enabled") : $("options")).focus({ preventScroll: true });
}

// Rubber-band resistance past a boundary, and Apple's momentum projection for a release velocity (px/s).
function rubberband(overshoot, dimension) {
  return (overshoot * dimension * 0.55) / (dimension + 0.55 * Math.abs(overshoot));
}
function project(velocity) {
  return ((velocity / 1000) * 0.998) / (1 - 0.998);
}

// Offsets are the moving element's on-screen position, so grabbing it mid-transition continues from where it is.
function trackDrag(target, axis, accept, move, end, moving = target) {
  target.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || !accept(event)) return;
    const position = (e) => (axis === "x" ? e.clientX : e.clientY);
    const start = position(event);
    const base = new DOMMatrix(getComputedStyle(moving).transform)[axis === "x" ? "m41" : "m42"];
    let history = [{ offset: base, time: event.timeStamp }];
    let dragging = false;
    const onMove = (e) => {
      const offset = position(e) - start;
      if (!dragging) {
        if (Math.abs(offset) < 8) return;
        dragging = true;
        target.setPointerCapture(event.pointerId);
      }
      history = [...history.slice(-4), { offset: base + offset, time: e.timeStamp }];
      move(base + offset);
    };
    const onEnd = () => {
      removeEventListener("pointermove", onMove);
      removeEventListener("pointerup", onEnd);
      removeEventListener("pointercancel", onEnd);
      if (!dragging) return;
      // Swallow the click that follows a drag so it does not activate what is under the pointer.
      const swallow = (e) => e.stopPropagation();
      addEventListener("click", swallow, { capture: true, once: true });
      setTimeout(() => removeEventListener("click", swallow, true));
      const first = history[0];
      const last = history[history.length - 1];
      end(last.offset, ((last.offset - first.offset) / Math.max(1, last.time - first.time)) * 1000);
    };
    addEventListener("pointermove", onMove);
    addEventListener("pointerup", onEnd);
    addEventListener("pointercancel", onEnd);
  });
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
      (data.repositoryError || null) !== (snapshot?.repositoryError || null);
    snapshot = data;
    if (repositoryChanged)
      feedback(data.repositoryError || "Repository updated.");
    render();
  } catch (error) {
    $("state").textContent = "Unavailable";
    $("state-chip").className = "chip off";
    feedback(`Could not load scan results: ${error.message}`);
    if (!snapshot) {
      const box = element("div", undefined, "group empty");
      box.id = "empty";
      box.append(
        element("strong", "Scan results are unavailable"),
        element("p", "Retrying…"),
      );
      $("rows").replaceChildren(box);
    }
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
      feedback(
        `${id === "enabled" ? "Scanning" : id === "deep" ? "Deep scan" : "Show unidentified scripts"} ${value ? "enabled" : "disabled"}.`,
      );
    } catch (error) {
      $(id).checked = snapshot?.settings[setting] ?? !value;
      feedback(`Could not save setting: ${error.message}`);
    } finally {
      $(id).disabled = false;
      settingWrites--;
      refresh();
    }
  };
}
// Resume hides itself once scanning is on, so move focus to a control that stays visible.
$("resume").onclick = async () => {
  $("enabled").checked = true;
  await $("enabled").onchange();
  if (document.activeElement === document.body)
    ($("rescan").disabled ? $("search") : $("rescan")).focus();
};
$("search").oninput = render;
$("rows").addEventListener("pointerdown", () => {
  pressing = true;
});
for (const type of ["pointerup", "pointercancel"])
  addEventListener(type, () => {
    pressing = false;
    setTimeout(render);
  });
$("rows").onkeydown = (event) => {
  const keys = ["ArrowDown", "ArrowUp", "Home", "End"];
  if (!keys.includes(event.key) || !event.target.matches(".row")) return;
  const rows = [...$("rows").querySelectorAll(".row")];
  const index = rows.indexOf(event.target);
  const next = {
    ArrowDown: Math.min(index + 1, rows.length - 1),
    ArrowUp: Math.max(index - 1, 0),
    Home: 0,
    End: rows.length - 1,
  }[event.key];
  event.preventDefault();
  rows[next].focus();
};
$("options").onclick = () => setSheet(true);
$("done").onclick = () => setSheet(false);
$("scrim").onclick = () => setSheet(false);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.body.classList.contains("sheet-open")) {
    event.preventDefault();
    setSheet(false);
  } else if ((event.key === "Escape" || (event.altKey && event.key === "ArrowLeft")) && pushed) {
    event.preventDefault();
    closeLibrary();
  }
});
// Drag from the detail view's left edge to go back; momentum decides whether it pops.
trackDrag(
  $("details"),
  "x",
  (event) => event.clientX - $("details").getBoundingClientRect().left < 24,
  (offset) => {
    const width = $("details").offsetWidth;
    const x = Math.max(0, offset);
    const progress = Math.min(1, Math.max(0, x / width));
    for (const node of [$("details"), $("list-view"), document.querySelector(".dim")])
      node.style.transition = "none";
    $("list-view").style.visibility = "visible";
    $("details").style.transform = `translateX(${x}px)`;
    $("list-view").style.transform = `translateX(${-30 * (1 - progress)}%)`;
    document.querySelector(".dim").style.opacity = String(0.5 * (1 - progress));
  },
  (offset, velocity) => {
    for (const node of [$("details"), $("list-view"), document.querySelector(".dim")])
      node.style.transition = node.style.transform = node.style.opacity = node.style.visibility = "";
    if (offset + project(velocity) > $("details").offsetWidth / 2) closeLibrary();
  },
);
// Drag the sheet down to dismiss it; dragging up meets increasing resistance.
trackDrag(
  $("sheet-handle"),
  "y",
  (event) => !event.target.closest("button"),
  (offset) => {
    $("sheet").style.transition = "none";
    $("sheet").style.transform = `translateY(${offset < 0 ? -rubberband(-offset, 300) : offset}px)`;
  },
  (offset, velocity) => {
    $("sheet").style.transition = $("sheet").style.transform = "";
    if (offset + project(velocity) > $("sheet").offsetHeight / 2) setSheet(false);
  },
  $("sheet"),
);
$("rescan").onclick = async () => {
  revision++;
  $("rescan").disabled = true;
  try {
    const [tab] = await extensionCall("tabs", "query", {
      active: true,
      currentWindow: true,
    });
    const result = await extensionCall("runtime", "sendMessage", {
      type: "rescan",
      tabId: tab?.id,
      url: tab?.url,
    });
    if (typeof result?.rescanned !== "number")
      throw new Error(result?.error || "No response.");
    selected = null;
    closeLibrary();
    feedback(
      result.rescanned
        ? `Rescanning ${plural(result.rescanned, "script", "scripts")}.`
        : "Results cleared. Reload the page to scan scripts loaded earlier.",
    );
  } catch (error) {
    feedback(`Could not refresh: ${error.message}`);
  } finally {
    $("rescan").disabled = false;
    refresh();
  }
};
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
  feedback("Full scan data exported.");
};
refresh();
setInterval(refresh, 1000);
