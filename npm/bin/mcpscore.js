#!/usr/bin/env node
// mcpscore npm wrapper: runs the Python mcpscore CLI at the exact version
// this package pins (package.json -> mcpscore.pythonVersion), so
// `npx @mcp-box/mcpscore <target>` runs the matching Python release.
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
  // 0 ok, 1 usage error, 2 connection failure, 3 score gate, 4 smoke gate).
  process.exit(result.status === null ? 1 : result.status);
}

tryRun("uvx", [spec]);
tryRun("pipx", ["run", spec]);

// Show a harmless verification command, not a reconstruction of argv: targets
// and flags can contain credentials, and quoting differs across user shells.
const installCommand = process.platform === "win32"
  ? "winget install --id=astral-sh.uv -e"
  : "curl -LsSf https://astral.sh/uv/install.sh | sh";

console.error(
  [
    `mcpscore needs a Python runner (this npm package launches ${spec}).`,
    "Neither uvx nor pipx was found on PATH. Node.js alone is not enough.",
    "",
    "1. Install uv (includes uvx):",
    `   ${installCommand}`,
    "   Other installation methods: https://docs.astral.sh/uv/getting-started/installation/",
    "2. Open a new terminal, then verify:",
    "   uvx --version",
    "   npx @mcp-box/mcpscore --help",
    "3. Retry your original command.",
    "",
    "Already installed uv or pipx? Ensure its executable directory is on PATH.",
    "The wrapper does not install a runner automatically.",
    "Docs: https://docs.mcpscore.dev",
  ].join("\n"),
);
process.exit(1);
