/* global chrome, console */

(function() {
	var count = 0;
	var totalResults = [];
	chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
		if (request.message) {
			var result = JSON.parse(request.message);
			totalResults.push(result);
			if (result.vulnerable) {
				count++;
				sendResponse({'count' : count});
				var out = [];
				result.results.forEach(function(r) {
					out.push(r.component + " " + r.version + " - Info: " + r.vulnerabilities.join(" "))
				})
				console.warn("Loaded script with known vulnerabilities: " + result.url + "\n - " + out.join("\n - "));
			}
		} else if (request.getDetected) {
			sendResponse(totalResults);
		}
	});
})();
