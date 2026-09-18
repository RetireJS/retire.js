window.addEventListener(
  "message",
  (event) => {
    if (
      event.source !== parent ||
      !event.data ||
      typeof event.data.script !== "string"
    )
      return;
    const receiver = event.source;
    const send = receiver.postMessage.bind(receiver);
    for (const name of ["alert", "prompt", "confirm"])
      Object.defineProperty(window, name, { value() {}, configurable: false });
    try {
      document.querySelector("base").href = new URL("/", event.data.url).href;
      new Function("top", event.data.script)(window);
    } catch {
      /* A library may expect globals absent from this sandbox. */
    }
    for (const [component, funcs] of Object.entries(event.data.repoFuncs)) {
      for (const expression of funcs) {
        try {
          const version = eval(expression);
          if (typeof version === "string") send({ component, version }, "*");
        } catch {
          /* Not every extractor applies to each script. */
        }
      }
    }
    send({ done: true }, "*");
  },
  { once: true },
);
