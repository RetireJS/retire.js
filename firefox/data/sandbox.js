self.port.on("testScript", function (script, repoFuncs) {
    try {
        // For some reason http://erlend.oftedal.no/blog/retire/dojo.js fails when eval'd
        eval(script);
    	for(var component in repoFuncs) {
        	repoFuncs[component].forEach(function(func) {
            	try {
                	var result = eval(func);
                	self.port.emit("result", { component : component, version : result })

            	} catch(e) {
            	}
        	});
    	}
	} catch(e) {
	}
});