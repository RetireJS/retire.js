var realwin = window;
var realdoc = document;

window.addEventListener("message", function(evt) {
    //console.log('inner', evt, evt.data);
    if (!evt.data.script) return evt.source.postMessage({ done : "true"}, "*");
    var repoFuncs = evt.data.repoFuncs;
    //try {
        ['alert', 'prompt', 'confirm'].forEach(function(n) {
            try {
                Object.defineProperty(window, n, {
                    get: function() { return function() {} },
                    set: function() { },
                    enumerable: true,
                    configurable: false
                });
            } catch(e) {}
        });

        //Make sure other scripts are loaded correctly
        if (evt.data.url) {
            document.getElementsByTagName("base")[0].setAttribute("href", evt.data.url.replace(/(https?:\/\/[^\/]+).*/, "$1/"));
        }

        //Anti framebusting
        window.fun = new Function('top', evt.data.script);
        window.fun(window);

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
    /*} catch(e) {
        console.warn(e);
    }*/
    evt.source.postMessage({ done : "true"}, "*");
});

