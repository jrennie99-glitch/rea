// Structured console logging + an append-only security event log.
// Secrets are never passed here; callers redact before logging.
import { appendFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { config } from "./config.mjs";

mkdirSync(config.dataDir, { recursive: true });
const BLOCK_LOG = resolve(config.dataDir, "block.log");

const stamp = () => new Date().toISOString();

export const log = {
  info: (msg, extra) => console.log(`${stamp()} ℹ ${msg}`, extra ?? ""),
  warn: (msg, extra) => console.warn(`${stamp()} ⚠ ${msg}`, extra ?? ""),
  error: (msg, extra) => console.error(`${stamp()} ✖ ${msg}`, extra ?? ""),
};

// Append-only, one JSON object per line. Best-effort: a logging failure must
// never crash a request path, but it also must never be silently swallowed in
// a way that hides a real disk problem — so we surface it once to stderr.
export function blockEvent(event) {
  const record = { ts: stamp(), ...event };
  try {
    appendFileSync(BLOCK_LOG, JSON.stringify(record) + "\n");
  } catch (err) {
    log.error("could not write block log", err?.message);
  }
  return record;
}
