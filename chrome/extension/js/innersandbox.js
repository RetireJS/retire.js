var realwin = window;
var realdoc = document;
console.log("inner sandbox loaded");

window.addEventListener("message", function (evt) {
  //console.log('inner', evt, evt.data);
  if (!evt.data.script) return evt.source.postMessage({ done: "true" }, "*");
  var repoFuncs = evt.data.repoFuncs;
  console.log("I'm trying!!");
  //try {
  ["alert", "prompt", "confirm"].forEach(function (n) {
    try {
      Object.defineProperty(window, n, {
        get: function () {
          return function () {};
        },
        set: function () {},
        enumerable: true,
        configurable: false,
      });
    } catch (e) {}
  });

  //Make sure other scripts are loaded correctly
  if (evt.data.url) {
    document
      .getElementsByTagName("base")[0]
      .setAttribute(
        "href",
        evt.data.url.replace(/(https?:\/\/[^\/]+).*/, "$1/")
      );
  }

  //Anti framebusting
  window.fun = new Function("top", evt.data.script);
  try {
    console.log("SANDBOX invoking", evt.data.url);
    window.fun(window);
  } catch (e) {
    console.warn("SANDBOX ERROR", e);
  }
  Object.entries(repoFuncs).forEach(([component, funcs]) => {
    funcs.forEach(function (func) {
      try {
        var result = eval(func);
        console.log("SANDBOX eval", component, result);
        evt.source.postMessage(
          { component: component, version: result, original: evt.data },
          "*"
        );
      } catch (e) {
        //if (component == "nextjs") console.log("SANDBOX ERROR", e);
      }
    });
  });
  /*} catch(e) {
    console.warn(e);
  }*/
  evt.source.postMessage({ done: "true" }, "*");
});
