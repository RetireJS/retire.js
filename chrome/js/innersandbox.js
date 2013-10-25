
window.addEventListener("message", function(evt) {
    var repoFuncs = evt.data.repoFuncs;
    try {
    	eval(evt.data.script);
    	for(var component in repoFuncs) {
    		repoFuncs[component].forEach(function(func) {
    			try {
    				var result = eval(func);
    				console.log(component, result)
    				evt.source.postMessage({ component : component, version : result, original: evt.data }, "*");
    			} catch(e) {
    			}
    		});
    	}
    } catch(e) {
    }
    evt.source.postMessage({ done : "true"}, "*");
});

