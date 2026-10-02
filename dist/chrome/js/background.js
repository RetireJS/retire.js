// The privileged offscreen document only manages isolated sandbox frames.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (
    sender.id !== chrome.runtime.id ||
    sender.tab ||
    message.target !== "offscreen" ||
    message.type !== "sandbox"
  )
    return false;
  const iframe = document.createElement("iframe");
  const results = [];
  let finished = false;
  function finish(error) {
    if (finished) return;
    finished = true;
    clearTimeout(timeout);
    window.removeEventListener("message", receive);
    iframe.remove();
    sendResponse({ results, error });
  }
  function receive(event) {
    if (
      event.source !== iframe.contentWindow ||
      event.origin !== "null" ||
      !event.data
    )
      return;
    if (event.data.done) return finish();
    const { component, version } = event.data;
    if (
      Object.hasOwn(message.repoFuncs, component) &&
      typeof version === "string" &&
      version.length <= 100
    )
      results.push({ component, version });
  }
  const timeout = setTimeout(
    () => finish("Function detection timed out"),
    10000,
  );
  window.addEventListener("message", receive);
  iframe.addEventListener(
    "load",
    () =>
      iframe.contentWindow.postMessage(
        {
          script: message.content,
          url: message.url,
          repoFuncs: message.repoFuncs,
        },
        "*",
      ),
    { once: true },
  );
  iframe.src = "inner-sandbox.html";
  document.body.appendChild(iframe);
  return true;
});
