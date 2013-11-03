self.port.on("detect-version", function (script, repoFuncs) {

  console.log("sandbox.js - detect-version");

  // Solution 1
  // Load the script in a script element and try the repo functions in order to find a version string.
  // Works, but seems hacky and creates leaks
  // Problem: the page-worker's destroy method does not remove the background window object causing the add-on to leak (see lib/main, line 170).
  // The GC will not remove the window probably because objects are still alive in the sanbox.html document.
  // I have not found a working way to clean up the added script's/object.
  // We could make the page-worker global in the add-on to avoid all the background pages, but then the background page will pile up with scripts and
  // The page needs to be 'fresh' each time a script is added in order to not create conflicts between scripts etc.

  /**
   * Since the dom can be modified by a script, content scripts transparently access the original dom values in something called XRayWrapper.
   * The actual dom lives in window.unsafeWindow so we need to look there to find user objects.
   * Since 'window' has cyclic values we need to get the visible values only, get the unsafeWindow reference and run our eval inside the unsafeWindow.
   * 
   * More information about this here:
   * https://addons.mozilla.org/en-US/developers/docs/sdk/latest/dev-guide/guides/content-scripts/accessing-the-dom.html
   * https://bugzilla.mozilla.org/show_bug.cgi?id=787070
   * https://bugzilla.mozilla.org/show_bug.cgi?id=787013
   * https://bugzilla.mozilla.org/show_bug.cgi?id=934296
   */
      
  var scriptEl = document.createElement("script");
  scriptEl.setAttribute("type", "text/javascript");
  scriptEl.text = script;
  document.head.appendChild(scriptEl);

  // Hack, the following gets the unsafeWindow where user added objects lives and runs the test in unsafeWindow
  var visible = [];
  var windowAsString = JSON.stringify(window, function(key, val) {
    if (typeof val == "object") {
      if (visible.indexOf(val) >= 0) {
        return;
      }
      visible.push(val);
    }
    return val;
  });
  var unsafeWindow = JSON.parse(windowAsString).unsafeWindow;
  with(unsafeWindow) {
    for(var component in repoFuncs) {
      repoFuncs[component].forEach(function(func) {
        try {
          var result = eval(func);
          self.port.emit("version-detected", { component : component, version : result })
        } catch(e) {
        }
      });
    }
  }
  
  /*  
  // Solution 2
  // Create a new Iframe and load the script in the iframe's window
  // Problem: Can not access the window. TypeError: window/contentWindow is a cyclic object value
  
  var head = document.getElementsByTagName("head")[0];
  var iframe = document.createElement("iframe");

  iframe.onload = function () {
    var scriptEl = iframe.contentDocument.createElement("script");
    scriptEl.setAttribute("type", "text/javascript");
    scriptEl.text = script;
    iframe.contentDocument.getElementsByTagName('head')[0].appendChild(scriptEl);
    console.log(iframe.contentWindow); // TypeError: object is a cyclic object value
    console.log(iframe.contentWindow.wrappedJSObject);
  };
  document.body.appendChild(iframe);
  */
  
  /*
  // Solution 3
  // eval the script/text blob, try finding the library version
  // This works in chrome background scripts
  // The problem with this is that libraries sometimes contains detector code accessing 'window' object and what not
  // that is problematic running in a content/xray document ?
  // (eval() added before the try/catch to better see the exceptions)
  eval(script);
  try {
    // For some reason the following scripts fails fails when eval'd
    // http://erlend.oftedal.no/blog/retire/dojo.js
    // http://cdnjs.cloudflare.com/ajax/libs/backbone.js/0.3.3/backbone-min.js

    for(var component in repoFuncs) {
      repoFuncs[component].forEach(function(func) {
        try {
          var result = eval(func);
          self.port.emit("version-detected", { component : component, version : result })
        } catch(e) {}
      });
    }
  } catch(e) {}
  */
  
  // Notify the add-on so it can destroy the pageWorker instance
  self.port.emit("done");
  
});