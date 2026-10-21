const { startRuntime } = require("./runtime");
const engine = require("../..");

startRuntime(typeof browser === "undefined" ? chrome : browser, engine, {
  sandbox: FUNCTION_SCANNING,
});
