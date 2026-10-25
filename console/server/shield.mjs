// ── Threat Shield ────────────────────────────────────────────────────────────
// Defends the console's HTTP surface. Blocking mode: the console is a normal
// app, so a tripped trap means ban — it is NOT a research/observation platform.
// Real signatures and counters; no security theatre.
//
//   • per-IP sliding-window rate limiting
//   • attack-signature WAF (matched AFTER recursive URL-decode)
//   • honeypot decoy paths + a hidden form-field trap → instant ban
//   • escalating, auto-expiring IP bans, persisted across restarts
//   • append-only block log
//
// Trusted-proxy handling never lets a spoofed X-Forwarded-For forge an IP:
// XFF is read only when REA_CONSOLE_TRUST_PROXY is explicitly on.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { config } from "./config.mjs";
import { blockEvent, log } from "./log.mjs";

const BANS_FILE = resolve(config.dataDir, "bans.json");

// Decoy paths no real user or legitimate crawler of THIS app ever requests.
export const HONEYPOT_PATHS = new Set([
  "/wp-login.php",
  "/wp-admin",
  "/xmlrpc.php",
  "/.env",
  "/.env.local",
  "/.git/config",
  "/.git/HEAD",
  "/admin.php",
  "/phpmyadmin",
  "/phpMyAdmin",
  "/actuator/env",
  "/actuator/health",
  "/api/v1/keys",
  "/config.json",
  "/aws/credentials",
  "/.aws/credentials",
  "/server-status",
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
]);

// Name of the hidden input the UI renders off-screen. Any human leaves it
// empty; a form-filling bot fills it.
export const HONEYPOT_FIELD = "contact_url_confirm";

// Attack signatures. Case-insensitive; evaluated against the decoded string.
const WAF = [
  [/\b(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\()/i, "sqli"],
  [/(\$where|\$ne\b|\$gt\b|\$regex\b|\{\s*"\$)/i, "nosqli"],
  [/(<script\b|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*=\s*["']?\s*x)/i, "xss"],
  [/(\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|\/proc\/self\/|\bboot\.ini\b)/i, "path-traversal"],
  [/(file:\/\/|php:\/\/|zip:\/\/|data:text\/|expect:\/\/)/i, "lfi-rfi"],
  [/(;\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b|\|\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b|\$\(|`.*`)/i, "cmd-injection"],
  [/(\$\{jndi:|jndi:(ldap|rmi|dns|iiop):|\$\{env:|\$\{sys:)/i, "jndi-log4shell"],
  [/(\{\{.*\}\}|\$\{.*\}|<%=.*%>|#\{.*\})/i, "template-injection"],
  [/(%0d|%0a|\r\n)(set-cookie|location|content-length)/i, "crlf"],
];

// Offensive-scanner user agents.
const SCANNER_UA =
  /(sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|feroxbuster|nuclei|httpx\b|zgrab|curl\/7\.(?!.*legit)|python-requests|go-http-client|hydra|metasploit)/i;

// Ban escalation ladder (ms).
const LADDER = [10 * 60e3, 60 * 60e3, 24 * 60 * 60e3, 7 * 24 * 60 * 60e3];

/** @type {Map<string, {until:number, strikes:number}>} */
const bans = new Map();
/** @type {Map<string, number[]>} */
const hits = new Map();

(function loadBans() {
  try {
    const data = JSON.parse(readFileSync(BANS_FILE, "utf8"));
    const now = Date.now();
    for (const [ip, rec] of Object.entries(data)) {
      if (rec?.until > now) bans.set(ip, rec);
    }
    if (bans.size) log.info(`shield: restored ${bans.size} active ban(s)`);
  } catch {
    /* no persisted bans yet */
  }
})();

function persistBans() {
  try {
    writeFileSync(BANS_FILE, JSON.stringify(Object.fromEntries(bans)));
  } catch (err) {
    log.error("shield: could not persist bans", err?.message);
  }
}

// Recursively URL-decode so encoded payloads can't slip past the signatures.
function fullyDecode(s) {
  let prev = s ?? "";
  for (let i = 0; i < 3; i++) {
    let next;
    try {
      next = decodeURIComponent(prev.replace(/\+/g, " "));
    } catch {
      break;
    }
    if (next === prev) break;
    prev = next;
  }
  return prev;
}

/** Resolve the real client IP, honouring XFF only when explicitly trusted. */
export function clientIp(req) {
  if (config.trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    if (xff) return String(xff).split(",")[0].trim().replace(/^::ffff:/, "");
  }
  return (req.socket?.remoteAddress || "unknown").replace(/^::ffff:/, "");
}

function ban(ip, reason, detail) {
  const prev = bans.get(ip);
  const strikes = (prev?.strikes ?? 0) + 1;
  const span = LADDER[Math.min(strikes - 1, LADDER.length - 1)];
  const rec = { until: Date.now() + span, strikes };
  bans.set(ip, rec);
  persistBans();
  blockEvent({ kind: "ban", ip, reason, detail, strikes, until: new Date(rec.until).toISOString() });
  log.warn(`shield: banned ${ip} (${reason}, strike ${strikes}, ${Math.round(span / 60e3)}min)`);
}

function banned(ip) {
  const rec = bans.get(ip);
  if (!rec) return false;
  if (rec.until <= Date.now()) {
    bans.delete(ip);
    persistBans();
    return false;
  }
  return true;
}

function rateExceeded(ip) {
  const now = Date.now();
  const windowStart = now - 60e3;
  const arr = (hits.get(ip) || []).filter((t) => t > windowStart);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > config.ratePerMin;
}

/**
 * Inspect an incoming request.
 * @returns {{allow:true, ip:string} | {allow:false, status:number, reason:string, ip:string}}
 */
export function guard(req, bodyText = "") {
  const ip = clientIp(req);

  if (banned(ip)) {
    blockEvent({ kind: "reject", ip, reason: "active-ban", path: req.url });
    return { allow: false, status: 403, reason: "banned", ip };
  }

  const ua = String(req.headers["user-agent"] || "");
  const url = req.url || "/";
  const path = url.split("?")[0];

  // Honeypot: decoy path → instant ban.
  if (HONEYPOT_PATHS.has(path)) {
    ban(ip, "honeypot-path", path);
    return { allow: false, status: 404, reason: "not-found", ip };
  }

  // Scanner UA.
  if (SCANNER_UA.test(ua)) {
    ban(ip, "scanner-ua", ua.slice(0, 120));
    return { allow: false, status: 403, reason: "forbidden", ip };
  }

  // WAF over the decoded URL + body.
  const haystack = fullyDecode(url) + "\n" + fullyDecode(bodyText);
  for (const [re, label] of WAF) {
    if (re.test(haystack)) {
      ban(ip, `waf:${label}`, path);
      return { allow: false, status: 403, reason: "forbidden", ip };
    }
  }

  // Hidden-field trap (filled by bots only).
  if (bodyText) {
    try {
      const parsed = JSON.parse(bodyText);
      if (parsed && typeof parsed === "object" && parsed[HONEYPOT_FIELD]) {
        ban(ip, "honeypot-field", HONEYPOT_FIELD);
        return { allow: false, status: 400, reason: "bad-request", ip };
      }
    } catch {
      /* non-JSON body handled elsewhere */
    }
  }

  // Rate limit (does not escalate to a ban on its own — transient 429).
  if (rateExceeded(ip)) {
    blockEvent({ kind: "throttle", ip, path });
    return { allow: false, status: 429, reason: "rate-limited", ip };
  }

  return { allow: true, ip };
}

export function shieldStats() {
  const now = Date.now();
  let active = 0;
  for (const rec of bans.values()) if (rec.until > now) active++;
  return { activeBans: active, trackedIps: hits.size };
}
