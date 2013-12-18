const { Cc, Ci } = require("chrome");
const events = require("sdk/event/core");

exports.run = function(script, repoFuncs, details, callback) {
  let container = {};
  let appShellService = Cc["@mozilla.org/appshell/appShellService;1"].
                          getService(Ci.nsIAppShellService);
  container.hiddenWindow = appShellService.hiddenDOMWindow;
  container.doc = container.hiddenWindow.document;
  container.iframe = container.doc.createElement("iframe");
  container.iframe.addEventListener("DOMContentLoaded", (event) => {
    container.iframeDoc = event.target;
    container.scriptEl = container.iframeDoc.createElement("script");
    container.scriptEl.type = "text/javascript";
    container.scriptEl.text = script;
    container.iframeDoc.body.appendChild(container.scriptEl);
    with(container.iframe.contentWindow) {
      for(let component in repoFuncs) {
        repoFuncs[component].forEach(function(func) {
          try {
            let objectName = func.split(".")[0];
            let result = eval(func);
            callback({ component: component, version: result }, details);
          } catch(e) {
          }
          let objectName = func.split(".")[0];
          delete container.iframe.contentWindow[objectName];
        });
      }
    }
    container.iframe.parentNode.removeChild(container.iframe);
    for (let key in container) {
      delete container[key];
    }
  });
  container.hiddenWindow.document.documentElement.appendChild(container.iframe);
}