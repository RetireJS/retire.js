/*
(function() {
        var count = 0;
        chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
                if (request.message) {
                        count++;
                        chrome.runtime.sendMessage({'count' : count});
                        console.warn(request.message);
                }
        });
})();
*/


var count = 0;

self.port.on("fisk", function(tag) {
	

	count++;
	self.port.emit("ost", {count: count});
});
