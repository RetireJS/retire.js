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
      () => {
        chrome.action.setIcon({
          path: this.checked ? "icons/icon48.png" : "icons/icon_bw48.png",
        });
        sendMessage("enable", this.checked, null);
      },
      false
    );
    document.querySelector("input[type=checkbox]#deepEnabled").addEventListener(
      "click",
      () => {
        sendMessage("deepScanEnable", this.checked, null);
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

function queryForResults() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    chrome.tabs.sendMessage(
      tabs[0].id,
      { getDetected: 1 },
      function (response) {
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

  const vulnerabilities = results.reduce((acc, rs) => {
    return (
      acc +
      rs.results.reduce((acc, r) => {
        return acc + (r.vulnerabilities ? r.vulnerabilities.length : 0);
      }, 0)
    );
  }, 0);
  document.querySelector("#stats").innerHTML = `<span>URLs scanned: ${
    results.length
  }</span> <span class="${
    vulnerabilities.length > 0 ? "vuln" : ""
  }">Vulnerabilities found: ${vulnerabilities}</span>`;

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
  res.sort((x, y) => {
    if (x.unknown != y.unknown) {
      return x.unknown ? 1 : -1;
    }
    if (x.vulnerable != y.vulnerable) {
      return x.vulnerable ? -1 : 1;
    }
    return (x.component + x.version + x.url).localeCompare(
      y.component + y.version + y.url
    );
  });
  res.forEach((r) => {
    let tr = document.createElement("tr");
    document.getElementById("results").appendChild(tr);
    let vulns;
    if (r.unknown) {
      tr.className = "unknown";
      td(tr).innerText = "-";
      td(tr).innerText = "-";
      vulns = td(tr);
      vulns.innerHTML = `Did not recognize ${r.url}`;
    } else {
      td(tr).innerText = r.component;
      td(tr).innerText = r.version;
      vulns = td(tr);
      let d = detMapping[r.detection] ?? r.detection;
      vulns.innerHTML = `${r.url} (${d} detection)`;
    }
    if (r.vulnerabilities && r.vulnerabilities.length > 0) {
      r.vulnerabilities.sort((x, y) => {
        return severityMap[y.severity] - severityMap[x.severity];
      });
      const severity = mapSeverity(r.vulnerabilities);
      tr.className = "vulnerable " + severity;
      var table = document.createElement("table");
      vulns.appendChild(table);
      r.vulnerabilities.forEach(function (v) {
        var tr = document.createElement("tr");
        tr.className = v.severity;
        table.appendChild(tr);
        td(tr).innerText = v.severity || " ";
        td(tr).innerText = v.identifiers
          ? v.identifiers
              .mapOwnProperty(function (val) {
                return val;
              })
              .flatten()
              .join(" ")
          : " ";
        let info = td(tr);
        info.className = "info";
        v.info.forEach(function (u, i) {
          var a = document.createElement("a");
          a.innerText = i + 1;
          a.href = u;
          a.title = u;
          a.target = "_blank";
          info.appendChild(a);
        });
      });
    }
  });
}
function td(tr) {
  let cell = document.createElement("td");
  tr.appendChild(cell);
  return cell;
}

Object.prototype.forEachOwnProperty = function (f) {
  mapOwnProperty(f);
};
Object.prototype.mapOwnProperty = function (f) {
  var results = [];
  for (var i in this) {
    if (this.hasOwnProperty(i)) results.push(f(this[i], i));
  }
  return results;
};

Array.prototype.flatten = function () {
  return this.reduce((a, b) => a.concat(b), []);
};

function sendMessage(message, data, callback) {
  chrome.runtime.sendMessage(
    { to: "background", message: message, data: data },
    (response) => {
      callback && callback(response);
    }
  );
}
