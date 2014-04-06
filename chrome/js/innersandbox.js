
window.addEventListener("message", function(evt) {
    var repoFuncs = evt.data.repoFuncs;
    try {

        //Make sure other scripts are loaded correctly
        document.getElementsByTagName("base")[0].setAttribute("href", evt.data.url.replace(/(https?:\/\/[^\/]+).*/, "$1/"));

        //stop framebusting
        var valueof = function() { return evt.data.url };
        var f = function() {};
        var fakewin = { 
            location: { 
                replace: f, assign: f, reload:f, valueOf: valueof, hash: "",
                href : { replace: f, valueOf: valueof } },
        };
        fakewin.top = fakewin;
        fakewin.document = { location : fakewin.location };
        var fun = new Function('window, document, top', evt.data.script);
        fun(fakewin, fakewin.document, fakewin);


        for(var component in repoFuncs) {
            repoFuncs[component].forEach(function(func) {
                try {
                    var result = eval(func);
                    console.log(component, result);
                    evt.source.postMessage({ component : component, version : result, original: evt.data }, "*");
                } catch(e) {
                }
            });
        }
    } catch(e) {
        //console.log(e);
    }
    evt.source.postMessage({ done : "true"}, "*");
});

