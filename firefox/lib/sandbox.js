const { Cc, Ci } = require("chrome");
const events = require("sdk/event/core");

exports.run = function(script, repoFuncs, eventTarget, details) {
  let appShellService = Cc["@mozilla.org/appshell/appShellService;1"].
                          getService(Ci.nsIAppShellService);
  let hiddenWindow = appShellService.hiddenDOMWindow;
  let doc = hiddenWindow.document;
  let iframe = doc.createElement("iframe");
  iframe.addEventListener("DOMContentLoaded", (event) => {
    let iframeDoc = event.target;
    let scriptEl = iframeDoc.createElement("script");
    scriptEl.type = "text/javascript";
    scriptEl.text = script;
    iframeDoc.body.appendChild(scriptEl);
    with(iframe.contentWindow) {
      for(let component in repoFuncs) {
        repoFuncs[component].forEach(function(func) {
          try {
            let result = eval(func);
            events.emit(eventTarget, "sandbox-version-detected", { 
              component: component,
              version: result 
            }, details);
          } catch(e) {
          }
        });
      }
    }
    iframe.parentNode.removeChild(iframe);
  });
  hiddenWindow.document.documentElement.appendChild(iframe);
}