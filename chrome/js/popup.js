window.addEventListener('load', function() {
	sendMessage('enabled?', null, function(response) { 
		document.querySelector("input[type=checkbox]").checked = response.enabled;
	});
	document.querySelector("input[type=checkbox]").addEventListener('click', function() {
		console.log(this.checked);
		chrome.browserAction.setIcon({ path: this.checked ? "icons/icon48.png" : "icons/icon_bw48.png" });
		sendMessage('enable', this.checked, null);
	}, false);
	queryForResults();
	setInterval(queryForResults, 5000);

}, false);

function queryForResults() {
	chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
	  chrome.tabs.sendMessage(tabs[0].id, {getDetected: 1}, function(response) {
	    show(response);
	    console.log(response);
	  });
	});	
}

function show(results) {
	document.getElementById("results").innerHTML="";
	results.forEach(function(rs) {
		rs.results.forEach(function(r) {
			var tr = document.createElement("tr");
			document.getElementById("results").appendChild(tr);				
			td(tr).innerText = r.component;
			td(tr).innerText = r.version;
			var vulns = td(tr);
			vulns.innerHTML = "Found in " + rs.url;
			if (r.vulnerabilities && r.vulnerabilities.length > 0) {
				tr.className = "vulnerable";
				vulns.innerHTML += "<br>Vulnerability info: " + r.tagline;
				r.vulnerabilities.forEach(function(v, i) { 
					var a = document.createElement("a");
					a.innerText = i + 1;
					a.href = v;
					a.title = v;
					a.target = "_blank";
					vulns.appendChild(a);
				})
			}
		})
	})
}
function td(tr) {
	var cell = document.createElement("td");
	tr.appendChild(cell);
	return cell;
}

function sendMessage(message, data, callback) {
	chrome.extension.sendRequest({ to: 'background', message: message, data: data }, function(response) { callback && callback(response) });
}