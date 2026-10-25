// Manage a disposable, isolated Chrome instance for website analysis.
// REA attaches to a loopback CDP endpoint; we launch one, point it at the URL,
// hand the endpoint to REA, then tear it down and delete the throwaway profile.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:net";
import { join } from "node:path";
import { config } from "./config.mjs";
import { log } from "./log.mjs";

const MAC_CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
];
const LINUX_CANDIDATES = ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];

export function resolveChrome() {
  if (config.chromePath && existsSync(config.chromePath)) return config.chromePath;
  const list = process.platform === "darwin" ? MAC_CANDIDATES : LINUX_CANDIDATES;
  return list.find((p) => existsSync(p)) || null;
}

// SSRF guard: the console runs locally under your permissions, so localhost is
// fair game (analysing your own dev server), but cloud metadata and link-local
// ranges are blocked so a pasted link can't pivot into infrastructure.
const BLOCKED_HOSTS = [
  /^169\.254\./, // link-local (incl. 169.254.169.254 metadata)
  /^fe80:/i,
  /\bmetadata\.google\.internal$/i,
];

export function urlAllowed(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return { ok: false, reason: "not a valid URL" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, reason: "only http/https targets are supported" };
  }
  if (BLOCKED_HOSTS.some((re) => re.test(u.hostname))) {
    return { ok: false, reason: "host is in a blocked internal/metadata range" };
  }
  return { ok: true, url: u };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function waitForCdp(port, deadlineMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < deadlineMs) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`, {
        signal: AbortSignal.timeout(1500),
      });
      if (res.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

/**
 * Launch Chrome on a fresh loopback CDP endpoint, navigated to `url`.
 * @returns {Promise<{endpoint:string, port:number, targetId:string|null, close:()=>void}>}
 */
export async function launchForUrl(url, { onProgress } = {}) {
  const bin = resolveChrome();
  if (!bin) throw new Error("no Chrome-family browser found — set REA_CONSOLE_CHROME");

  const port = await freePort();
  const profileDir = mkdtempSync(join(tmpdir(), "rea-console-chrome-"));
  const endpoint = `http://127.0.0.1:${port}`;

  onProgress?.(`launching ${bin.split("/").pop()} on CDP ${endpoint}`);
  const child = spawn(
    bin,
    [
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${profileDir}`,
      "--headless=new",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-sync",
      "--remote-allow-origins=*",
      url,
    ],
    { stdio: "ignore", detached: false },
  );

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    try {
      child.kill("SIGKILL");
    } catch {
      /* already gone */
    }
    try {
      rmSync(profileDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  };
  child.on("exit", () => (closed = true));

  const up = await waitForCdp(port);
  if (!up) {
    close();
    throw new Error("Chrome did not expose its CDP endpoint in time");
  }

  // Give the page a moment to settle, then find the page target for this URL.
  await new Promise((r) => setTimeout(r, 800));
  let targetId = null;
  try {
    const res = await fetch(`${endpoint}/json`, { signal: AbortSignal.timeout(3000) });
    const targets = await res.json();
    const page = targets.find((t) => t.type === "page" && t.url && !t.url.startsWith("devtools://"));
    targetId = page?.id ?? null;
  } catch (err) {
    log.warn("could not enumerate CDP targets", err?.message);
  }

  return { endpoint, port, targetId, close };
}
