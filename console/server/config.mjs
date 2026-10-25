// Configuration loader. Reads a local .env (no dependency) then the process
// environment, and derives a frozen config object the rest of the app reads.
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
export const APP_ROOT = resolve(here, "..");
export const REPO_ROOT = resolve(APP_ROOT, "..");

// Minimal .env parser: KEY=VALUE lines, # comments, optional surrounding quotes.
// We never log values and never overwrite an already-set process.env var.
function loadDotEnv(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return;
  }
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    if (!key || key in process.env) continue;
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadDotEnv(resolve(APP_ROOT, ".env"));

const env = process.env;
const bool = (v, d) => (v == null ? d : /^(1|true|yes|on)$/i.test(v));
const int = (v, d) => {
  const n = Number.parseInt(v ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : d;
};

const bind = env.REA_CONSOLE_BIND || "127.0.0.1";
const isLoopback = bind === "127.0.0.1" || bind === "::1" || bind === "localhost";

// REA requires Node 22.x (>=22.19), 24.x (>=24.11), or 26+. The server may be
// launched under any Node, so resolve a supported interpreter to SPAWN the
// engine with, independent of whatever runs this process.
function resolveReaNode() {
  if (env.REA_CONSOLE_NODE && existsSync(env.REA_CONSOLE_NODE)) return env.REA_CONSOLE_NODE;
  const [maj, min] = process.versions.node.split(".").map(Number);
  const selfSupported =
    (maj === 22 && min >= 19) || (maj === 24 && min >= 11) || maj >= 26;
  if (selfSupported) return process.execPath;
  const candidates = [
    "/opt/homebrew/opt/node@24/bin/node",
    "/opt/homebrew/opt/node@22/bin/node",
    "/usr/local/opt/node@24/bin/node",
    "/usr/local/opt/node@22/bin/node",
  ];
  return candidates.find((p) => existsSync(p)) || process.execPath;
}

// ── Agent brain selection ────────────────────────────────────────────────
// Open-source first: if nothing is configured, default to a local OpenAI-
// compatible server (Ollama). An explicit base URL or an Anthropic key
// overrides. No key is required for the local path.
const explicitLlmBase = env.REA_CONSOLE_LLM_BASE_URL || "";
const hasAnthropic = Boolean(env.ANTHROPIC_API_KEY);
const llmBackend = explicitLlmBase ? "openai" : hasAnthropic ? "anthropic" : "openai";
const llmBaseUrl =
  llmBackend === "openai" ? (explicitLlmBase || "http://127.0.0.1:11434/v1") : "";
const llmModel =
  env.REA_CONSOLE_LLM_MODEL ||
  (llmBackend === "anthropic" ? env.REA_CONSOLE_MODEL || "claude-opus-5-5" : "qwen2.5:3b");
// Dummy key keeps OpenAI-compatible servers (Ollama/LM Studio/llama.cpp) happy;
// hosted gateways (OpenRouter, Together, Groq…) take a real one here.
const llmKey = env.REA_CONSOLE_LLM_KEY || "ollama";

// Optional two-model pipeline (OpenAI/local backend only): the driver above
// does the tool-calling to gather evidence, then this writer model synthesises
// the final teardown. Plays a tool-capable model (qwen) against a stronger
// writer (e.g. ornith). Default on for the local setup; set empty to disable.
const localDefault = llmBackend === "openai" && !explicitLlmBase;
const llmWriter =
  env.REA_CONSOLE_LLM_WRITER !== undefined
    ? env.REA_CONSOLE_LLM_WRITER
    : localDefault
      ? "ornith-uncensored:latest"
      : "";

export const config = Object.freeze({
  port: int(env.REA_CONSOLE_PORT, 7749),
  bind,
  isLoopback,
  // A token is optional on loopback, mandatory off it.
  token: env.REA_CONSOLE_TOKEN || "",
  tokenRequired: !isLoopback || Boolean(env.REA_CONSOLE_TOKEN),

  backend: llmBackend,
  anthropicKey: env.ANTHROPIC_API_KEY || "",
  llmBaseUrl,
  llmModel,
  llmWriter: llmBackend === "openai" ? llmWriter : "",
  llmKey,
  model: llmModel, // display label
  agentEnabled: true, // a backend always exists (local default); health reports reachability

  reaBin: env.REA_BIN || resolve(REPO_ROOT, "scripts", "rea.mjs"),
  reaNode: resolveReaNode(),
  chromePath: env.REA_CONSOLE_CHROME || "",

  trustProxy: bool(env.REA_CONSOLE_TRUST_PROXY, false),
  ratePerMin: int(env.REA_CONSOLE_RATE_PER_MIN, 120),
  cmdTimeoutMs: int(env.REA_CONSOLE_CMD_TIMEOUT_MS, 180000),

  appRoot: APP_ROOT,
  repoRoot: REPO_ROOT,
  dataDir: resolve(APP_ROOT, "data"),
  publicDir: resolve(APP_ROOT, "public"),
});
