(function () {
  "use strict";

  var extension = null;

  window.addEventListener("message", function (evt) {
    try {
      if (evt.data && evt.data.repoFuncs) {
        console.log("SANDBOX: received scan request", evt.data.url);
        extension = evt.source;

        var iframe = document.createElement("iframe");
        iframe.retireEvent = evt;
        iframe.src = "inner-sandbox.html";

        // True isolation; we don't need same-origin
        iframe.setAttribute("sandbox", "allow-scripts");

        iframe.setAttribute("data-url", evt.data.url);
        iframe.style.display = "none";
        document.body.appendChild(iframe);

        setTimeout(function () {
          try { iframe.contentWindow.postMessage(evt.data, "*"); }
          catch (err) { console.warn("SANDBOX ERROR posting to iframe", err); }
        }, 200);

        setTimeout(function () {
          try { iframe.remove(); }
          catch (err) { console.warn("SANDBOX ERROR removing iframe", err); }
        }, 10000);
      } else if (evt.data && evt.data.version) {
        extension && extension.postMessage(evt.data, "*");
      }
    } catch (err) {
      console.warn("SANDBOX ERROR outer handler", err);
    }
  });
})();
