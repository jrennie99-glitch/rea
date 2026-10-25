# REA Console

A premium web cockpit for the [REA](../README.md) engine. Paste a link, drop a
local app path, or just describe a target — the console drives REA to tear it
down and shows you the evidence, how it works, and how to rebuild it.

It lives **inside** the REA repo but is fully isolated from REA's build/CI
pipeline (not a workspace; excluded from `oxlint`/`oxfmt`; outside `turbo`,
`knip`, `jscpd`, and `tsc` globs). It has **zero runtime dependencies** — Node
built-ins only — so there's nothing to install and no supply-chain surface.

---

## Run

```bash
cd console
./start.sh
# → http://127.0.0.1:7749
```

`start.sh` picks a REA-supported Node (22.x/24.x/26+). The console also spawns
the `rea` CLI with a supported Node automatically, even if you launch the server
some other way, so the engine never trips REA's Node-version gate.

Optional config — copy `.env.example` to `.env`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `REA_CONSOLE_PORT` | `7749` | Listen port |
| `REA_CONSOLE_BIND` | `127.0.0.1` | Bind address. Loopback = local-only. |
| `REA_CONSOLE_TOKEN` | — | Bearer token. Optional on loopback, **required** off it. |
| `ANTHROPIC_API_KEY` | — | Enables **Agent mode**. Empty = Direct mode only. |
| `REA_CONSOLE_MODEL` | `claude-opus-5-5` | Agent model (switch to `claude-sonnet-5-5` / `claude-haiku-5-5` to cut cost). |
| `REA_BIN` | `../scripts/rea.mjs` | REA CLI entry |
| `REA_CONSOLE_CHROME` | auto | Chrome-family browser for website analysis |
| `REA_CONSOLE_NODE` | auto | Node used to spawn the engine |

---

## Two modes

- **Direct mode** (no key) — paste a URL or a local path and the console maps it
  to the right REA commands and streams real evidence back. Websites launch a
  disposable headless Chrome, attach over CDP, and run `inspect-web-page`,
  `analyze-web-bundle`, and `capture-web-screenshot`. Local artifacts run
  `analyze-javascript-application`, `inspect-wasm-artifact`,
  `inspect-managed-artifact`, `inspect-binary-layout`, `inspect-android-package`,
  or `inspect-artifact`.
- **Agent mode** (needs `ANTHROPIC_API_KEY`) — Claude drives the REA toolset +
  web search to handle natural-language targets, GitHub repos, and multi-step
  investigations, then writes an evidence-backed teardown with a rebuild plan.

The mode toggle (`Auto` / `Direct` / `Agent`) chooses per run; `Auto` uses Agent
when the target needs it and the LLM is reachable, otherwise Direct.

---

## Native binaries (Ghidra)

Decompiling native binaries (Mach-O / ELF / PE → pseudocode) needs an external
analysis engine. REA drives an existing **Ghidra 12.1.x** install; point it at
one with env vars (the console passes them through to the engine it spawns, so
they belong in `.env`):

```
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC
JAVA_HOME=/absolute/path/to/jdk-21   # a full JDK 21+ (must include javac)
```

**Apple Silicon note:** the official 12.1.4 release ships decompiler binaries
only for `linux_x86_64` and `win_x86_64`. On an arm64 Mac you must build the
native decompiler from the source included in the release, then drop it in:

```bash
cd "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/src/decompile/cpp"
make clean
make ghidra_opt ARCH_TYPE="-arch arm64" \
  ADDITIONAL_FLAGS="-mmacosx-version-min=11.0 -w" OSDIR=mac_arm_64
mkdir -p ../os/mac_arm_64
cp ghidra_opt ../os/mac_arm_64/decompile
```

Verify with `rea doctor` (the `ghidra` check should read `healthy`) or the
console's **Engine check** button. Without this, every other target still works;
only native decompilation is gated on it.

---

## Security

This server shells out to a powerful analysis tool, so it ships hardened:

- **Safe exec** — the `rea` CLI is run via `execFile` with an argv array, never a
  shell; a deny-by-default allowlist limits it to read-only inspect/analyze
  commands. No target string can inject a command.
- **Threat Shield** on the HTTP surface — attack-signature WAF (matched after
  URL-decoding), honeypot decoy paths + a hidden form-field trap (instant ban),
  per-IP rate limiting, escalating auto-expiring bans persisted across restarts,
  and an append-only block log (`data/block.log`). Blocking mode — the console is
  a normal app, not an observation platform.
- **No XFF spoofing** — `X-Forwarded-For` is trusted only when
  `REA_CONSOLE_TRUST_PROXY=true`, so a forged header can't fake an IP or ban a
  third party.
- **SSRF guard** — website analysis allows `http/https` only and blocks
  link-local / cloud-metadata ranges.
- **Prompt-injection defense** — in Agent mode, everything a tool returns (page
  text, decompiled code, search results) is treated as untrusted DATA; the model
  is instructed never to follow instructions embedded in analyzed material.
- **Headers** — CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` on every response. No secrets in the client
  bundle; the API key stays server-side. Bind to loopback unless you add a token.

`data/` (bans, block log) is gitignored.

---

## Layout

```
console/
  server/
    index.mjs    HTTP server, routing, SSE, static, auth
    config.mjs   env/.env loading, derived config
    shield.mjs   Threat Shield (WAF, honeypot, bans, rate limit)
    rea.mjs      safe REA CLI bridge (allowlist, execFile)
    browser.mjs  disposable Chrome + CDP for website analysis
    detect.mjs   target auto-detection
    direct.mjs   Direct-mode orchestration
    agent.mjs    Agent-mode Claude tool-use loop
    log.mjs      logging + append-only block log
  public/        index.html · app.css · app.js  (zero-dep UI)
```
