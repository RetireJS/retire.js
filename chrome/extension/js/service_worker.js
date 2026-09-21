const { startRuntime } = require("./runtime");
const engine = require("../../build");

startRuntime(typeof browser === "undefined" ? chrome : browser, engine, {
  sandbox: FUNCTION_SCANNING,
});
