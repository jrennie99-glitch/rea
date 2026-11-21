// Console access control + filesystem confinement. Pure, dependency-free and
// fail-closed: any doubt denies. Used by index.mjs (HTTP gate) and agent/direct
// (path confinement).
import { createHash, timingSafeEqual } from "node:crypto";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";

export const COOKIE_NAME = "rea_console";
export const MIN_REMOTE_TOKEN = 32;

const sha = (s) => createHash("sha256").update(String(s)).digest();

/** Constant-time token compare. Empty / non-string on either side is always false. */
export function tokenMatches(presented, expected) {
  if (typeof presented !== "string" || typeof expected !== "string") return false;
  if (presented.length === 0 || expected.length === 0) return false;
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(sha(presented), sha(expected));
}

/** Refuse unsafe configurations. Throws; the caller exits non-zero. */
export function validateStartup(cfg) {
  if (typeof cfg.token !== "string" || cfg.token.length === 0) {
    throw new Error("no console token configured");
  }
  if (!cfg.isLoopback && cfg.token.length < MIN_REMOTE_TOKEN) {
    throw new Error(
      `REA_CONSOLE_BIND=${cfg.bind} is not loopback: REA_CONSOLE_TOKEN must be set and at least ${MIN_REMOTE_TOKEN} characters`,
    );
  }
}

function allowedHosts(cfg) {
  const set = new Set([`127.0.0.1:${cfg.port}`, `localhost:${cfg.port}`, `[::1]:${cfg.port}`]);
  for (const h of cfg.allowedHosts || []) set.add(h.toLowerCase());
  return set;
}

/** Anti DNS-rebinding. Skipped only for an explicit non-loopback bind with no host allow-list. */
export function hostOk(req, cfg) {
  const host = String(req.headers.host || "").toLowerCase();
  if (!cfg.isLoopback && !(cfg.allowedHosts || []).length) return host.length > 0;
  return allowedHosts(cfg).has(host);
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/**
 * Gate for /api/*. Returns {ok:true} or {ok:false,status,error}.
 * Token: `Authorization: Bearer` or the httpOnly cookie. Origin must be same-origin;
 * a state-changing request without Origin is accepted only with an explicit
 * Authorization header (a browser cannot attach one cross-origin without a preflight).
 */
export function apiGate(req, cfg) {
  const method = String(req.method || "GET").toUpperCase();
  const stateChanging = !["GET", "HEAD", "OPTIONS"].includes(method);
  const h = req.headers;

  const auth = String(h["authorization"] || "");
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const cookie = parseCookies(h["cookie"])[COOKIE_NAME] || "";
  const viaBearer = tokenMatches(bearer, cfg.token);
  const viaCookie = tokenMatches(cookie, cfg.token);
  if (!viaBearer && !viaCookie) return { ok: false, status: 401, error: "unauthorized" };

  const site = h["sec-fetch-site"];
  if (site && site !== "same-origin" && site !== "none") {
    return { ok: false, status: 403, error: "cross-site request refused" };
  }

  const origin = h["origin"];
  if (origin !== undefined) {
    const host = String(h.host || "").toLowerCase();
    if (String(origin).toLowerCase() !== `http://${host}` && String(origin).toLowerCase() !== `https://${host}`) {
      return { ok: false, status: 403, error: "origin not allowed" };
    }
  } else if (stateChanging && !viaBearer) {
    return { ok: false, status: 403, error: "origin required" };
  }

  if (stateChanging) {
    const ct = String(h["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (ct !== "application/json") return { ok: false, status: 415, error: "content-type must be application/json" };
  }
  return { ok: true };
}

export function sessionCookie(token) {
  return `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/`;
}

// ── Filesystem confinement ───────────────────────────────────────────────
const SENSITIVE_DIRS = [
  ".ssh", ".aws", ".config", ".gnupg", ".kube", ".docker", ".azure", ".gcloud",
  ".password-store", ".cache", "Keychains", "Cookies",
];
const SENSITIVE_HOME_PATHS = [
  ".ssh", ".aws", ".config", ".gnupg", ".kube", ".docker", ".azure",
  "Library/Keychains", "Library/Cookies", "Library/Application Support/Google/Chrome",
  "Library/Application Support/Firefox", "Library/Safari",
];
const SENSITIVE_FILE = /^(\.env(\..*)?|\.npmrc|\.netrc|\.pgpass|\.git-credentials|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|.*\.(pem|key|p12|pfx|keychain|keychain-db|kdbx))$/i;

export function workspaceRoot(env = process.env) {
  return realpathSync(resolve(env.REA_WORKSPACE || process.cwd()));
}

const inside = (root, p) => {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
};

/**
 * Confine a caller-supplied path to the workspace. Returns {ok:true,path}
 * (the realpath) or {ok:false,reason}. Never throws.
 */
export function confinePath(raw, { root: rootOverride, env = process.env, home = homedir() } = {}) {
  try {
    let p = String(raw ?? "");
    if (!p || p.includes("\0")) return { ok: false, reason: "invalid path" };
    if (p === "~" || p.startsWith("~/")) p = home + p.slice(1);
    if (p.split(/[\\/]+/).includes("..")) return { ok: false, reason: "path traversal ('..') is not allowed" };
    const root = rootOverride ? realpathSync(rootOverride) : workspaceRoot(env);
    const abs = resolve(root, p);
    let real;
    try {
      real = realpathSync(abs);
    } catch {
      return { ok: false, reason: "path not found or not accessible" };
    }
    if (!inside(root, real)) return { ok: false, reason: "path is outside the allowed workspace" };
    let realHome = home;
    try { realHome = realpathSync(home); } catch { /* keep */ }
    for (const s of SENSITIVE_HOME_PATHS) {
      let sp = resolve(realHome, s);
      try { sp = realpathSync(sp); } catch { /* nonexistent: lexical */ }
      if (inside(sp, real)) return { ok: false, reason: "sensitive path is not allowed" };
    }
    const segs = relative(root, real).split(sep).filter(Boolean);
    if (segs.some((s) => SENSITIVE_DIRS.includes(s)) || SENSITIVE_FILE.test(basename(real))) {
      return { ok: false, reason: "sensitive path is not allowed" };
    }
    return { ok: true, path: real };
  } catch {
    return { ok: false, reason: "path rejected" }; // fail closed
  }
}
