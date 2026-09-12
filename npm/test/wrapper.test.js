"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { readFileSync, mkdtempSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const pkg = require("../package.json");
const wrapper = path.join(__dirname, "../bin/mcpscore.js");
const source = readFileSync(wrapper, "utf8");
const missing = { error: { code: "ENOENT" } };

// Execute the shipped entry point, replacing only OS boundaries. No Python
// runners or network are needed, including on Windows.
function run(platform, args, outcomes) {
  const calls = [];
  const errors = [];
  const exited = {};
  let code;
  assert.throws(() => runInNewContext(source, {
    require(name) {
      if (name === "../package.json") return pkg;
      assert.equal(name, "node:child_process");
      return { spawnSync(command, argv, options) {
        calls.push({ command, argv: Array.from(argv), options });
        assert.ok(outcomes.length, "unexpected extra runner invocation");
        return outcomes.shift();
      } };
    },
    process: { platform, argv: ["node", wrapper, ...args], exit(value) {
      code = value;
      throw exited;
    } },
    console: { error(message) { errors.push(message); } },
  }), (error) => error === exited);
  return { calls, errors: errors.join("\n"), code };
}

for (const [platform, command] of [
  ["linux", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
  ["darwin", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
  ["win32", "winget install --id=astral-sh.uv -e"],
]) {
  test(`missing runners give recovery steps on ${platform}`, () => {
    const result = run(platform, ["--token", "private-token"], [missing, missing]);
    assert.equal(result.code, 1);
    assert.match(result.errors, /Python/);
    assert.ok(result.errors.includes(command));
    assert.match(result.errors, /new terminal/);
    assert.match(result.errors, /uvx --version/);
    assert.match(result.errors, /npx @mcp-box\/mcpscore --help/);
    assert.match(result.errors, /original command/);
    assert.ok(!result.errors.includes("private-token"));
  });
}

for (const code of [0, 1, 2, 3, 4]) {
  test(`uvx preserves arguments and exit ${code} without fallback`, () => {
    const args = ["--json", "--env", "NAME=a b", "--stdio", "node", "a path/server.js", "$(literal)"];
    const result = run("linux", args, [{ status: code }]);
    assert.equal(result.code, code);
    assert.equal(result.calls.length, 1);
    assert.deepEqual(result.calls[0].argv, [`mcpscore==${pkg.mcpscore.pythonVersion}`, ...args]);
    assert.equal(result.calls[0].command, "uvx");
    assert.equal(result.calls[0].options.stdio, "inherit");
    assert.ok(!result.calls[0].options.shell);
    assert.equal(result.errors, "");
  });
}

test("pipx is used only when uvx is absent", () => {
  const result = run("win32", ["--json", "a path/server.py"], [missing, { status: 3 }]);
  assert.equal(result.code, 3);
  assert.deepEqual(result.calls.map((call) => call.command), ["uvx", "pipx"]);
  assert.deepEqual(result.calls[1].argv, ["run", `mcpscore==${pkg.mcpscore.pythonVersion}`, "--json", "a path/server.py"]);
});

test("a runner launch error is not mistaken for an absent runner", () => {
  const result = run("linux", [], [{ error: { code: "EACCES", message: "permission denied" } }]);
  assert.equal(result.code, 1);
  assert.match(result.errors, /permission denied/);
  assert.equal(result.calls.length, 1);
});

test("a terminated runner does not trigger a second audit", () => {
  const result = run("linux", [], [{ status: null, signal: "SIGTERM" }]);
  assert.equal(result.code, 1);
  assert.equal(result.calls.length, 1);
});

test("real entry point fails cleanly with no runners and keeps stdout empty", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "mcpscore npm test "));
  try {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => key.toLowerCase() !== "path"));
    env.PATH = directory;
    const result = spawnSync(process.execPath, [wrapper, "--json"], { env, encoding: "utf8" });
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /uvx --version/);
    assert.match(result.stderr, /npx @mcp-box\/mcpscore --help/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
