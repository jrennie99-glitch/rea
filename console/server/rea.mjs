// Safe bridge to the local REA CLI.
//
// Hard rules enforced here:
//   • execFile with an argv array — NEVER a shell string. No interpolation, so
//     no command injection is possible regardless of what a target string holds.
//   • Deny-by-default allowlist: only curated read/inspect/analyze commands can
//     run. Anything that writes to a device or installs is intentionally absent.
//   • Every argument must be a plain string with no NUL byte and within a sane
//     length; options must come from a known-safe set.
import { execFile, spawn } from "node:child_process";
import { config } from "./config.mjs";
import { log } from "./log.mjs";

// Curated, read-only surface. Add commands deliberately, never with a wildcard.
export const ALLOWED_COMMANDS = new Set([
  // readiness / capability discovery
  "doctor",
  "capabilities",
  "list-architectures",
  // high-level overviews
  "analyze",
  "inspect",
  "analyze-javascript-application",
  // websites (driven against a CDP endpoint we launch)
  "list-browser-targets",
  "inspect-web-page",
  "analyze-web-bundle",
  "capture-web-screenshot",
  "discover-webmcp-tools",
  "inspect-web-network-capture",
  // code reading
  "decompile",
  "function",
  "instructions",
  "inspect-native-api",
  "inspect-native-load-image",
  // managed / .NET
  "inspect-managed-artifact",
  "inspect-managed-members",
  "inspect-managed-native-boundaries",
  // other static formats
  "inspect-wasm-artifact",
  "inspect-evm-interface",
  "inspect-binary-layout",
  "inspect-macho",
  "inspect-plist",
  "inspect-signature",
  "inspect-pe-resources",
  "inspect-artifact",
  "extract-artifact",
  // android (static apk only — no device writes)
  "inspect-android-package",
  "inspect-android-class",
  "inspect-android-method",
  "decode-android-resources",
]);

// Options we permit callers/agent to pass through, with their arity.
// Everything else is rejected before it reaches the CLI.
const ALLOWED_FLAGS = new Map([
  ["--observation-ms", 1],
  ["--allowed-origins", 1],
  ["--fetch-source-maps", 0],
  ["--include-accessibility-text", 0],
  ["--include-console-text", 0],
  ["--include-json-body-shapes", 0],
  ["--include-websocket-shapes", 0],
  ["--include-script-sources", 0],
  ["--include-storage-keys", 0],
  ["--target", 1],
  ["--client", 1],
  ["--provider", 1],
  ["--filter-output", 1],
  ["--token-limit", 1],
]);

const MAX_ARG_LEN = 4096;
const MAX_BUFFER = 24 * 1024 * 1024; // 24 MB of JSON is plenty; prevents memory blowups.

function validateArgs(command, args) {
  if (!ALLOWED_COMMANDS.has(command)) {
    throw new Error(`command not allowed: ${command}`);
  }
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (typeof a !== "string") throw new Error("arguments must be strings");
    if (a.includes("\0")) throw new Error("NUL byte in argument");
    if (a.length > MAX_ARG_LEN) throw new Error("argument too long");
    if (a.startsWith("--")) {
      const arity = ALLOWED_FLAGS.get(a);
      if (arity === undefined) throw new Error(`flag not allowed: ${a}`);
      out.push(a);
      if (arity === 1) {
        const val = args[++i];
        if (typeof val !== "string" || val.includes("\0") || val.length > MAX_ARG_LEN) {
          throw new Error(`invalid value for ${a}`);
        }
        out.push(val);
      }
    } else {
      out.push(a); // positional (endpoint, targetId, path, …)
    }
  }
  return out;
}

function parseOutput(stdout) {
  const text = stdout.trim();
  if (!text) return { json: null, text: "" };
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return { json: null, text };
  }
}

/**
 * Run a REA command and resolve with its parsed result.
 * @returns {Promise<{ok:boolean, command:string, json:any, text:string, stderr:string, code:number|null}>}
 */
export function runRea(command, args = [], { timeout = config.cmdTimeoutMs } = {}) {
  const safeArgs = validateArgs(command, args);
  const argv = [config.reaBin, command, ...safeArgs, "--format", "json"];
  return new Promise((resolve) => {
    execFile(
      config.reaNode,
      argv,
      { timeout, maxBuffer: MAX_BUFFER, cwd: config.repoRoot, env: process.env },
      (err, stdout, stderr) => {
        const { json, text } = parseOutput(stdout || "");
        const code = err?.code ?? 0;
        if (err && json == null) {
          log.warn(`rea ${command} exited ${code}`, (stderr || err.message || "").slice(0, 200));
        }
        resolve({
          ok: !err || json != null,
          command,
          json,
          text,
          stderr: (stderr || "").slice(0, 4000),
          code: typeof code === "number" ? code : null,
        });
      },
    );
  });
}

/**
 * Streaming variant: forwards stderr progress lines via onProgress, resolves
 * with the same shape as runRea once the process exits.
 */
export function runReaStream(command, args = [], { timeout = config.cmdTimeoutMs, onProgress } = {}) {
  const safeArgs = validateArgs(command, args);
  const argv = [config.reaBin, command, ...safeArgs, "--format", "json"];
  return new Promise((resolve) => {
    const child = spawn(config.reaNode, argv, { cwd: config.repoRoot, env: process.env });
    let stdout = "";
    let stderr = "";
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      child.kill("SIGKILL");
    }, timeout);

    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => {
      const chunk = String(d);
      stderr += chunk;
      if (onProgress) {
        for (const line of chunk.split(/\r?\n/)) {
          const t = line.trim();
          if (t) onProgress(t.slice(0, 300));
        }
      }
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ ok: false, command, json: null, text: "", stderr: err.message, code: null });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const { json, text } = parseOutput(stdout);
      resolve({
        ok: !killed && (code === 0 || json != null),
        command,
        json,
        text,
        stderr: stderr.slice(0, 4000),
        code: killed ? null : code,
      });
    });
  });
}
