#!/usr/bin/env node
// REA Console HTTP server. Zero runtime dependencies — Node built-ins only.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { config } from "./config.mjs";
import { log } from "./log.mjs";
import { guard, shieldStats } from "./shield.mjs";
import { detectTarget } from "./detect.mjs";
import { runDirect } from "./direct.mjs";
import { runAgent } from "./agent.mjs";
import { runRea } from "./rea.mjs";
import { resolveChrome } from "./browser.mjs";
import { apiGate, confinePath, hostOk, sessionCookie, tokenMatches, validateStartup } from "./security.mjs";

const MAX_BODY = 256 * 1024;

const STATIC = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.css": { file: "app.css", type: "text/css; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
};

function send(res, status, type, body, extra = {}) {
  res.writeHead(status, {
    "content-type": type,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy":
      "default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; " +
      "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
    ...extra,
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sse(res) {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-content-type-options": "nosniff",
  });
  return (obj) => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify(obj)}\n\n`);
  };
}

async function handleAnalyze(req, res, bodyText) {
  let parsed;
  try {
    parsed = JSON.parse(bodyText || "{}");
  } catch {
    return send(res, 400, "application/json", JSON.stringify({ error: "invalid JSON" }));
  }
  const input = String(parsed.input || "").slice(0, 8192);
  const requestedMode = parsed.mode === "agent" || parsed.mode === "direct" ? parsed.mode : "auto";
  if (!input.trim()) {
    return send(res, 400, "application/json", JSON.stringify({ error: "input is required" }));
  }

  const target = detectTarget(input);
  // Resolve the mode: honour an explicit choice, else auto.
  let mode = requestedMode;
  if (mode === "auto") mode = target.needsAgent && config.agentEnabled ? "agent" : "direct";
  if (mode === "agent" && !config.agentEnabled) {
    return send(
      res,
      400,
      "application/json",
      JSON.stringify({ error: "Agent mode needs an ANTHROPIC_API_KEY. Add one and restart." }),
    );
  }
  if (mode === "direct" && target.needsAgent) {
    return send(
      res,
      400,
      "application/json",
      JSON.stringify({
        error: `"${target.label}" targets need Agent mode. ${config.agentEnabled ? "Switch the mode toggle to Agent." : "Add an ANTHROPIC_API_KEY to enable it."}`,
      }),
    );
  }

  // Local-path targets are confined to the workspace (no ../, symlink escapes, credential stores).
  if (target.detail?.path) {
    const c = confinePath(target.detail.path);
    if (!c.ok) return send(res, 403, "application/json", JSON.stringify({ error: `path refused: ${c.reason}` }));
    target.input = c.path;
    target.detail.path = c.path;
  }

  const emit = sse(res);
  const controller = new AbortController();
  req.on("close", () => controller.abort());

  emit({ type: "meta", target: { type: target.type, label: target.label, detail: target.detail }, mode });
  try {
    if (mode === "agent") await runAgent(target, emit, controller.signal);
    else await runDirect(target, emit);
  } catch (err) {
    log.error(`analyze failed (${mode})`, err?.message);
    emit({ type: "error", text: err?.message || "analysis failed" });
  } finally {
    emit({ type: "end" });
    if (!res.writableEnded) res.end();
  }
}

async function llmReachable() {
  if (config.backend === "anthropic") return Boolean(config.anthropicKey);
  try {
    const res = await fetch(`${config.llmBaseUrl}/models`, { signal: AbortSignal.timeout(1500) });
    return res.ok;
  } catch {
    return false;
  }
}

async function handleHealth(res) {
  const llmReady = await llmReachable();
  send(
    res,
    200,
    "application/json",
    JSON.stringify({
      ok: true,
      agentEnabled: config.agentEnabled,
      backend: config.backend,
      model: config.model,
      writer: config.llmWriter || null,
      llmReady,
      chrome: Boolean(resolveChrome()),
      reaBin: config.reaBin,
      shield: shieldStats(),
    }),
  );
}

async function handleDoctor(res) {
  const result = await runRea("doctor", [], { timeout: 60000 });
  send(res, 200, "application/json", JSON.stringify({ ok: result.ok, data: result.json, text: result.text }));
}

const server = createServer(async (req, res) => {
  const json403 = (status, error) => send(res, status, "application/json", JSON.stringify({ error }));
  // Anti DNS-rebinding: every request must carry an expected Host.
  if (!hostOk(req, config)) return json403(403, "host not allowed");
  const path0 = (req.url || "/").split("?")[0];

  // First visit with ?token=… : set the httpOnly session cookie, then strip it from the URL.
  if (req.method === "GET" && path0 === "/") {
    const q = new URL(req.url, "http://x").searchParams.get("token");
    if (q !== null) {
      if (!tokenMatches(q, config.token)) return json403(401, "unauthorized");
      return send(res, 302, "text/plain; charset=utf-8", "", { location: "/", "set-cookie": sessionCookie(config.token), "cache-control": "no-store" });
    }
  }

  // Auth + Origin + Content-Type gate on the whole API, before any body is read.
  if (path0.startsWith("/api/")) {
    const gate = apiGate(req, config);
    if (!gate.ok) return json403(gate.status, gate.error);
  }

  let bodyText = "";
  if (req.method === "POST") {
    try {
      bodyText = await readBody(req);
    } catch {
      return send(res, 413, "application/json", JSON.stringify({ error: "body too large" }));
    }
  }

  // Shield first — on everything.
  const verdict = guard(req, bodyText);
  if (!verdict.allow) {
    const bodies = {
      429: JSON.stringify({ error: "rate limited" }),
      403: "Forbidden",
      404: "Not found",
      400: "Bad request",
    };
    return send(res, verdict.status, "text/plain; charset=utf-8", bodies[verdict.status] || "Error");
  }

  const path = (req.url || "/").split("?")[0];

  // Static assets.
  if (req.method === "GET" && STATIC[path]) {
    try {
      const { file, type } = STATIC[path];
      const buf = await readFile(resolve(config.publicDir, file));
      return send(res, 200, type, buf);
    } catch {
      return send(res, 404, "text/plain", "Not found");
    }
  }

  // API (auth-gated when a token is required).
  if (path.startsWith("/api/")) {
    if (req.method === "GET" && path === "/api/health") return handleHealth(res);
    if (req.method === "POST" && path === "/api/doctor") return handleDoctor(res);
    if (req.method === "POST" && path === "/api/analyze") return handleAnalyze(req, res, bodyText);
    return send(res, 404, "application/json", JSON.stringify({ error: "no such endpoint" }));
  }

  return send(res, 404, "text/plain; charset=utf-8", "Not found");
});

try {
  validateStartup(config);
} catch (err) {
  log.error(`refusing to start: ${err.message}`);
  process.exit(1);
}

server.listen(config.port, config.bind, () => {
  log.info(`REA Console listening on ${config.bind}:${config.port}`);
  log.info(`agent mode: ${config.agentEnabled ? `on (${config.model})` : "off (set ANTHROPIC_API_KEY)"}`);
  log.info(`chrome: ${resolveChrome() || "not found"} · token: required${config.tokenFromEnv ? " (REA_CONSOLE_TOKEN)" : " (random per launch)"}`);
  const host = config.bind === "::1" ? "[::1]" : config.bind;
  log.info(`open: http://${host}:${config.port}/?token=${config.token}`);
});
