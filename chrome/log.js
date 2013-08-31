var count = 0;

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
	count++;
	chrome.runtime.sendMessage({count : count});
    console.warn(request.message);      
});