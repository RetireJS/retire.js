var extension = null;
window.addEventListener("message", function orig(evt) {
	if (evt.data.repoFuncs) {
		extension = evt.source;
		var iframe = document.createElement("iframe");
		iframe.retireEvent = evt;
		iframe.src = "inner-sandbox.html";
		iframe.style = "visibility: hidden";
		document.body.appendChild(iframe);
		setTimeout(function() {
			iframe.contentWindow.postMessage(evt.data, "*");
		}, 200);
		setTimeout(function() {
			iframe.remove();
		}, 1000);
	} else if (evt.data.version){
		extension.postMessage(evt.data, "*");
	}
});