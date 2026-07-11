#!/usr/bin/env node
// mcpscore npm wrapper: runs the Python mcpscore CLI at the exact version
// this package pins (package.json -> mcpscore.pythonVersion), so
// `npx mcpscore <target>` and `uvx mcpscore <target>` behave identically.
//
// Resolution order: uvx (uv) -> pipx. No implicit installs into the user's
// environment; if neither runner exists, print clear instructions and exit 1.
"use strict";

const { spawnSync } = require("node:child_process");

const pkg = require("../package.json");
const spec = `mcpscore==${pkg.mcpscore.pythonVersion}`;
const args = process.argv.slice(2);

/**
 * Run the CLI through one Python runner; returns only if the runner is absent.
 * @param {string} cmd - runner executable name
 * @param {string[]} prefix - runner arguments placed before the mcpscore args
 */
function tryRun(cmd, prefix) {
  const result = spawnSync(cmd, [...prefix, ...args], { stdio: "inherit" });
  if (result.error) {
    if (result.error.code === "ENOENT") return; // runner not installed — try the next one
    console.error(`mcpscore: failed to run ${cmd}: ${result.error.message}`);
    process.exit(1);
  }
  // Propagate the CLI's exit code (mcpscore's codes are a documented contract:
  // 0 ok, 1 usage error, 2 connection failure).
  process.exit(result.status === null ? 1 : result.status);
}

tryRun("uvx", [spec]);
tryRun("pipx", ["run", spec]);

console.error(
  [
    `mcpscore is a Python CLI (this npm package is a thin wrapper for ${spec}).`,
    "It needs one of these Python runners on your PATH:",
    "",
    "  uv    https://docs.astral.sh/uv/  (then this command just works)",
    "  pipx  https://pipx.pypa.io/",
    "",
    "Or install it directly:  pip install mcpscore",
    "Docs: https://docs.mcpscore.dev",
  ].join("\n"),
);
process.exit(1);
