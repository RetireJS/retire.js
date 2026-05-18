window.addEventListener(
  "load",
  () => {
    sendMessage("enabled?", null, (response) => {
      document.querySelector("input[type=checkbox]#enabled").checked =
        response.enabled;
    });
    sendMessage("deepScanEnabled?", null, (response) => {
      document.querySelector("input[type=checkbox]#deepEnabled").checked =
        response.enabled;
    });

    document.querySelector("input[type=checkbox]#enabled").addEventListener(
      "click",
      (e) => {
        chrome.action.setIcon({
          path: e.target.checked ? "icons/icon48.png" : "icons/icon_bw48.png",
        });
        sendMessage("enable", e.target.checked, null);
      },
      false
    );
    document.querySelector("input[type=checkbox]#deepEnabled").addEventListener(
      "click",
      (e) => {
        sendMessage("deepScanEnable", e.target.checked, null);
      },
      false
    );

    document.querySelector("input[type=checkbox]#unknown").addEventListener(
      "click",
      () => {
        const r = document.getElementById("results");
        if (r.className.includes("hideunknown")) {
          r.className = r.className.replace("hideunknown", "");
        } else {
          r.className += " hideunknown";
        }
      },
      false
    );

    queryForResults();
    setInterval(queryForResults, 5000);
  },
  false
);
let lastShown = "";

function queryForResults() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    chrome.tabs.sendMessage(
      tabs[0].id,
      { getDetected: 1 },
      function (response) {
        let dt = JSON.stringify(response);
        if (dt == lastShown) return;
        lastShown = dt;
        show(response);
        console.log(response);
      }
    );
  });
}
function mapSeverity(vulns) {
  if (vulns.some((v) => v.severity == "critical")) return "critical";
  if (vulns.some((v) => v.severity == "high")) return "high";
  if (vulns.some((v) => v.severity == "medium")) return "medium";
  if (vulns.some((v) => v.severity == "low")) return "low";
  return "high";
}
const severityMap = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};
const detMapping = {
  ast: "AST",
  uri: "URI",
  filename: "file name",
  filecontent: "file content",
};

function show(totalResults) {
  if (totalResults == null || totalResults == undefined) return;

  document.getElementById("results").innerHTML = "";
  console.log(totalResults);
  var merged = {};
  totalResults.forEach((rs) => {
    merged[rs.url] = merged[rs.url] || { url: rs.url, results: [] };
    rs.results.forEach((r) => {
      if (
        !merged[rs.url].results.some(
          (x) => x.component == r.component && x.version == r.version
        )
      ) {
        merged[rs.url].results.push(r);
      }
    });
  });

  let results = Object.values(merged);
  
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const vulnerabilities = results.reduce((acc, rs) => {
    return (
      acc +
      rs.results.reduce((acc, r) => {
        if (r.vulnerabilities) {
          r.vulnerabilities.forEach((v) => {
            if (v.severity in severityCounts) severityCounts[v.severity]++;
          });
        }
        return acc + (r.vulnerabilities ? r.vulnerabilities.length : 0);
      }, 0)
    );
  }, 0);
  document.querySelector("#stats").innerHTML = "";
  document.querySelector("#stats").appendChild(span(`URLs scanned: ${results.length}`));
  document.querySelector("#stats").appendChild(span(`Vulnerabilities found: ${vulnerabilities}`, vulnerabilities > 0 ? "vuln" : ""));
  ["critical", "high", "medium", "low"].forEach((severity) => {
    if (severityCounts[severity] > 0) {
      document.querySelector("#stats").appendChild(span(`${severity}: ${severityCounts[severity]}`, severity));
    }
  });

  results.forEach((rs) => {
    rs.results.forEach((r) => {
      r.url = rs.url;
      r.vulnerable = r.vulnerabilities && r.vulnerabilities.length > 0;
    });
    if (rs.results.length == 0) {
      rs.results = [{ url: rs.url, unknown: true, component: "unknown" }];
    }
  });
  let res = results.reduce((x, y) => {
    return x.concat(y.results);
  }, []);
  function severityScore(r) {
    if (r.unknown) return -1;
    if (r.vulnerabilities && r.vulnerabilities.length > 0) {
      return severityMap[mapSeverity(r.vulnerabilities)] ?? 0;
    }
    return 0;
  }
  res.sort((x, y) => {
    const sd = severityScore(y) - severityScore(x);
    if (sd !== 0) return sd;
    return (x.component + x.version + x.url).localeCompare(
      y.component + y.version + y.url
    );
  });
  res.forEach((r) => {


    if (r.unknown) {
      let div = document.createElement("div");
      document.getElementById("results").appendChild(div);
      div.className = "unknown";
      div.appendChild(span(r.url));
    } else {
      let details = document.createElement("details");
      document.getElementById("results").appendChild(details);

      let summary = document.createElement("summary");
      details.appendChild(summary);
      let body = document.createElement("div");
      body.className = "details-body";
      details.appendChild(body);
      summary.appendChild(span(`${r.component} ${r.version}`, "lib-name"));

      if (r.vulnerabilities && r.vulnerabilities.length > 0) {
        r.vulnerabilities.sort((x, y) => {
          return severityMap[y.severity] - severityMap[x.severity];
        });
        const severity = mapSeverity(r.vulnerabilities);
        details.className = "vulnerable " + severity;

        const counts = {};
        r.vulnerabilities.forEach((v) => {
          counts[v.severity] = (counts[v.severity] || 0) + 1;
        });
        ["critical", "high", "medium", "low"].forEach((sev) => {
          if (counts[sev]) {
            const badge = document.createElement("span");
            badge.textContent = `${sev}: ${counts[sev]}`;
            badge.classList.add("severity-badge", sev);
            summary.appendChild(badge);
          }
        });
      }

      let d = detMapping[r.detection] ?? r.detection;
      let urlDiv = document.createElement("div");
      urlDiv.className = "detection-url";
      urlDiv.textContent = `${r.url} (${d} detection)`;
      body.appendChild(urlDiv);

      if (r.vulnerabilities && r.vulnerabilities.length > 0) {
        r.vulnerabilities.forEach(function (v) {
          const vulnItem = document.createElement("details");
          vulnItem.className = "vuln-item " + (v.severity || "");
          body.appendChild(vulnItem);

          const vulnSummary = document.createElement("summary");
          vulnItem.appendChild(vulnSummary);

          vulnSummary.appendChild(span(v.severity || "unknown", "severity-text"));

          const ids = v.identifiers || {};
          const summarySpan = document.createElement("span");
          summarySpan.className = "vuln-summary";
          summarySpan.textContent = ids.summary || "";
          vulnSummary.appendChild(summarySpan);

          const vulnBody = document.createElement("div");
          vulnBody.className = "vuln-body";
          vulnItem.appendChild(vulnBody);

          const skipKeys = new Set(["githubID", "CVE", "summary"]);
          const allChips = [
            ...[ids.githubID, ...(ids.CVE || [])].filter(Boolean),
            ...Object.entries(ids)
              .filter(([k]) => !skipKeys.has(k))
              .flatMap(([, val]) => Array.isArray(val) ? val : [val])
              .filter(Boolean),
          ];
          if (allChips.length > 0) {
            const chipsDiv = document.createElement("div");
            chipsDiv.className = "id-chips";
            allChips.forEach((id) => chipsDiv.appendChild(span(id, "id-chip")));
            vulnBody.appendChild(chipsDiv);
          }

          if (v.details) {
            const detailsText = document.createElement("p");
            detailsText.className = "details-text";
            detailsText.textContent = v.details;
            vulnBody.appendChild(detailsText);
          }

          if (v.info && v.info.length > 0) {
            const ul = document.createElement("ul");
            ul.className = "info-links";
            vulnBody.appendChild(ul);
            v.info.forEach(function (u) {
              const li = document.createElement("li");
              const a = document.createElement("a");
              a.href = u;
              a.textContent = u;
              a.target = "_blank";
              li.appendChild(a);
              ul.appendChild(li);
            });
          }
        });
      }
    }
  });
}
function span(data, className) {
  const s = document.createElement("span");
  if (className) s.classList.add(className);
  s.textContent = data;
  return s;
}


function sendMessage(message, data, callback) {
  console.log("Sending message", message, data);
  chrome.runtime.sendMessage(
    { to: "background", message: message, data: data },
    (response) => {
      callback && callback(response);
    }
  );
}
