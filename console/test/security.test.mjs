// Run: node --test console/test/   (zero deps; spawns the real server on loopback)
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { confinePath, tokenMatches } from "../server/security.mjs";

const serverFile = resolve(fileURLToPath(new URL("../server/index.mjs", import.meta.url)));
const PORT = 17000 + Math.floor(Math.random() * 2000);
const TOKEN = "t".repeat(48);
const base = `http://127.0.0.1:${PORT}`;
let child;

before(async () => {
  child = spawn(process.execPath, [serverFile], {
    env: { PATH: process.env.PATH, REA_CONSOLE_PORT: String(PORT), REA_CONSOLE_TOKEN: TOKEN, REA_CONSOLE_LLM_BASE_URL: "http://127.0.0.1:9/v1" },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try { await fetch(base + "/app.css"); return; } catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  throw new Error("server did not start");
});
after(() => child?.kill());

const J = { "content-type": "application/json" };
const post = (headers, body = JSON.stringify({ input: "" })) =>
  fetch(base + "/api/analyze", { method: "POST", headers, body });
const bearer = { authorization: `Bearer ${TOKEN}` };

test("missing / empty / wrong token rejected", async () => {
  assert.equal((await post({ ...J })).status, 401);
  assert.equal((await post({ ...J, authorization: "Bearer " })).status, 401);
  assert.equal((await post({ ...J, authorization: "Bearer nope" })).status, 401);
  assert.equal((await fetch(base + "/api/health")).status, 401);
});
test("cross-origin POST rejected (even with a valid token)", async () => {
  const r = await post({ ...J, ...bearer, origin: "https://evil.example" });
  assert.equal(r.status, 403);
});
test("text/plain simple-request CSRF rejected", async () => {
  const r = await post({ "content-type": "text/plain", origin: "https://evil.example" }, '{"input":"https://x.example","mode":"agent"}');
  assert.ok([401, 403, 415].includes(r.status));
});
test("bad Host rejected (DNS rebinding)", async () => {
  const r = await new Promise((res, rej) => {
    import("node:http").then(({ request }) => {
      const q = request({ host: "127.0.0.1", port: PORT, path: "/api/health", headers: { host: `evil.example:${PORT}`, ...bearer } }, (m) => res(m.statusCode));
      q.on("error", rej); q.end();
    });
  });
  assert.equal(r, 403);
});
test("non-JSON content type rejected", async () => {
  const r = await post({ "content-type": "text/plain", ...bearer }, "x");
  assert.equal(r.status, 415);
});
test("valid token + same origin works; cookie flow works", async () => {
  assert.equal((await fetch(base + "/api/health", { headers: bearer })).status, 200);
  const r = await post({ ...J, ...bearer, origin: base });
  assert.equal(r.status, 400); // passed the gate, rejected by input validation
  const login = await fetch(base + `/?token=${TOKEN}`, { redirect: "manual" });
  assert.equal(login.status, 302);
  const ck = login.headers.get("set-cookie");
  assert.match(ck, /HttpOnly/); assert.match(ck, /SameSite=Strict/);
  const viaCookie = await post({ ...J, cookie: ck.split(";")[0], origin: base });
  assert.equal(viaCookie.status, 400);
  assert.equal((await post({ ...J, cookie: ck.split(";")[0] })).status, 403); // cookie auth needs Origin
  assert.equal((await fetch(base + "/?token=wrong", { redirect: "manual" })).status, 401);
});
test("tokenMatches rejects empty on either side", () => {
  assert.equal(tokenMatches("", ""), false);
  assert.equal(tokenMatches("a", ""), false);
  assert.equal(tokenMatches("", "a"), false);
  assert.equal(tokenMatches("abc", "abd"), false);
  assert.equal(tokenMatches("abc", "abc"), true);
});
test("non-loopback bind without a >=32 char token refuses to start", () => {
  for (const tok of ["", "short"]) {
    const r = spawnSync(process.execPath, [serverFile], {
      env: { PATH: process.env.PATH, REA_CONSOLE_BIND: "0.0.0.0", REA_CONSOLE_PORT: String(PORT + 1), REA_CONSOLE_TOKEN: tok },
      timeout: 5000, encoding: "utf8",
    });
    assert.equal(r.status, 1, `token=${JSON.stringify(tok)}`);
  }
});

// ── analyze_path confinement ─────────────────────────────────────────────
const ws = realpathSync(mkdtempSync(join(tmpdir(), "rea-ws-")));
const home = realpathSync(mkdtempSync(join(tmpdir(), "rea-home-")));
mkdirSync(join(ws, "app")); writeFileSync(join(ws, "app", "a.js"), "1");
writeFileSync(join(ws, ".env"), "SECRET=1");
mkdirSync(join(home, ".ssh")); writeFileSync(join(home, ".ssh", "id_rsa"), "k");
symlinkSync(join(home, ".ssh"), join(ws, "link"));
const opt = { root: ws, home };

test("confinePath: in-workspace allowed", () => {
  assert.equal(confinePath(join(ws, "app", "a.js"), opt).ok, true);
  assert.equal(confinePath("app", opt).ok, true);
});
test("confinePath: ../, symlink escape, ~/.ssh, outside root, .env rejected", () => {
  assert.equal(confinePath("../etc/passwd", opt).ok, false);
  assert.equal(confinePath(join(ws, "app", "..", "..", "x"), opt).ok, false);
  assert.equal(confinePath(join(ws, "link"), opt).ok, false);
  assert.equal(confinePath("~/.ssh", opt).ok, false);
  assert.equal(confinePath(join(home, ".ssh", "id_rsa"), opt).ok, false);
  assert.equal(confinePath("/etc/hosts", opt).ok, false);
  assert.equal(confinePath(join(ws, ".env"), opt).ok, false);
  const homeRoot = { root: home, home };
  assert.equal(confinePath("~/.ssh", homeRoot).ok, false); // sensitive even inside the root
});
