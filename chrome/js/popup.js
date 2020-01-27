window.addEventListener('load', function() {
	sendMessage('enabled?', null, function(response) { 
		document.querySelector("input[type=checkbox]#enabled").checked = response.enabled;
	});

	document.querySelector("input[type=checkbox]#enabled").addEventListener('click', function() {
		console.log(this.checked);
		chrome.browserAction.setIcon({ path: this.checked ? "icons/icon48.png" : "icons/icon_bw48.png" });
		sendMessage('enable', this.checked, null);
	}, false);

	document.querySelector("input[type=checkbox]#unknown").addEventListener('click', function() {
		console.log(this.checked);
		document.getElementById("results").className = this.checked ? "" : "hideunknown";
	}, false);

	queryForResults();
	setInterval(queryForResults, 5000);

}, false);

function queryForResults() {
	chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
	  chrome.tabs.sendMessage(tabs[0].id, { getDetected: 1 }, function(response) {
	    show(response);
	    console.log(response);
	  });
	});	
}

function show(totalResults) {
	document.getElementById("results").innerHTML="";
	console.log(totalResults);
	var merged = {};
	totalResults.forEach(rs => {
		merged[rs.url] = merged[rs.url] || { url: rs.url, results: [] };
		merged[rs.url].results = merged[rs.url].results.concat(rs.results);
	});

	var results = Object.keys(merged).map(k => merged[k]);
	results.forEach(function(rs) {
		rs.results.forEach(function(r) {
			r.url = rs.url;
			r.vulnerable = r.vulnerabilities && r.vulnerabilities.length > 0;
		});
		if (rs.results.length == 0) {
			rs.results = [{ url: rs.url, unknown: true, component: "unknown" }]
		}
	});
	var res = results.reduce(function(x, y) { return x.concat(y.results); }, []);
	res.sort(function(x, y) {
		if (x.vulnerable != y.vulnerable) { return x.vulnerable ? -1 : 1 }
		if (x.unknown != y.unknown) { return x.unknown ? 1 : -1 }
		return (x.component + x.version).localeCompare(y.component + y.version);
	});
	res.forEach(function(r) {
		var tr = document.createElement("tr");
		document.getElementById("results").appendChild(tr);				
		if (r.unknown) {
			tr.className = "unknown";
			td(tr).innerText = "-";
			td(tr).innerText = "-";
			td(tr).innerHTML = "Did not recognize " + r.url;
		} else {
			td(tr).innerText = r.component;
			td(tr).innerText = r.version;
			var vulns = td(tr);
			vulns.innerHTML = "Found in " + r.url;
		}
		if (r.vulnerabilities && r.vulnerabilities.length > 0) {
			tr.className = "vulnerable";
			vulns.innerHTML += "<br>Vulnerability info: ";
			var table = document.createElement("table");
			vulns.appendChild(table);
			r.vulnerabilities.forEach(function(v) {
				var tr = document.createElement("tr");
				table.appendChild(tr);
				td(tr).innerText = v.severity || " ";
				td(tr).innerText = v.identifiers ? v.identifiers.mapOwnProperty(function(val) { return val }).flatten().join(" ") : " ";
				var info = td(tr);
				v.info.forEach(function(u, i) {
					var a = document.createElement("a");
					a.innerText = i + 1;
					a.href = u;
					a.title = u;
					a.target = "_blank";
					info.appendChild(a);
				});
			})
		}
	})
}
function td(tr) {
	var cell = document.createElement("td");
	tr.appendChild(cell);
	return cell;
}

Object.prototype.forEachOwnProperty = function(f) {
	mapOwnProperty(f);
};
Object.prototype.mapOwnProperty = function(f) {
	var results = [];
	for(var i in this) {
		if (this.hasOwnProperty(i)) results.push(f(this[i], i));
	}
	return results;
};

Array.prototype.flatten = function() { return this.reduce((a,b) => a.concat(b), []) }

function sendMessage(message, data, callback) {
	chrome.extension.sendRequest({ to: 'background', message: message, data: data }, function(response) { callback && callback(response) });
}