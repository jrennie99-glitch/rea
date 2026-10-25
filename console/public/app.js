// REA Console — client. Zero dependencies.
const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

const state = {
  mode: "auto",
  running: false,
  abort: null,
  token: localStorage.getItem("rea.token") || "",
};

const inputBox = $("#inputBox");
const runBtn = $("#runBtn");
const detectChip = $("#detectChip");
const hint = $("#composerHint");
const workspace = $("#workspace");
const emptyState = $("#emptyState");
const feed = $("#feed");
const timeline = $("#timeline");
const historyList = $("#history");

// ── Health ──────────────────────────────────────────────────────────────
async function health() {
  try {
    const res = await api("/api/health");
    if (!res.ok) throw new Error();
    const h = await res.json();
    const modePill = $("#modePill");
    if (h.llmReady) {
      modePill.textContent = h.writer ? `agent · ${h.model} → ${h.writer}` : `agent · ${h.model}`;
      modePill.className = "pill pill-on";
      modePill.title = h.writer
        ? `backend: ${h.backend} · driver ${h.model}, writer ${h.writer}`
        : `backend: ${h.backend}`;
    } else {
      modePill.textContent = h.backend === "anthropic" ? "no API key" : "LLM offline";
      modePill.className = "pill pill-off";
      modePill.title = h.backend === "anthropic" ? "set ANTHROPIC_API_KEY" : `start your LLM server (${h.model})`;
    }
    const chromePill = $("#chromePill");
    chromePill.textContent = h.chrome ? "chrome ✓" : "no chrome";
    chromePill.className = "pill " + (h.chrome ? "pill-muted" : "pill-off");
  } catch {
    $("#modePill").textContent = "offline";
  }
}

// ── Fetch with optional bearer token ────────────────────────────────────
function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (state.token) headers["authorization"] = `Bearer ${state.token}`;
  return fetch(path, { ...opts, headers });
}

// ── Client-side target detection (mirror of the server; chip only) ───────
function detect(raw) {
  const s = (raw || "").trim();
  if (!s) return { type: "research", label: "Research" };
  if (/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/i.test(s)) return { type: "github", label: "GitHub repo" };
  if (/^https?:\/\//i.test(s)) return { type: "website", label: "Website" };
  if (/^(~\/|\/|\.\/|[a-zA-Z]:[\\/])/.test(s)) {
    if (/\.(wasm|wat)$/i.test(s)) return { type: "wasm", label: "WASM" };
    if (/\.apk$/i.test(s)) return { type: "android", label: "Android APK" };
    if (/\.(dll|exe)$/i.test(s)) return { type: "managed", label: "Managed binary" };
    if (/\.(so|dylib|a|o|bin|macho)$/i.test(s)) return { type: "native", label: "Native binary" };
    if (/\.(js|mjs|cjs|asar)$/i.test(s)) return { type: "javascript", label: "JavaScript app" };
    return { type: "artifact", label: "Local artifact" };
  }
  if (/^0x[0-9a-fA-F]{8,}$/.test(s)) return { type: "evm", label: "EVM bytecode" };
  return { type: "research", label: "Research" };
}

function refreshChip() {
  const d = detect(inputBox.value);
  detectChip.textContent = d.label;
  detectChip.dataset.type = d.type;
}

inputBox.addEventListener("input", refreshChip);
inputBox.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
    e.preventDefault();
    start();
  }
});

// ── Mode toggle ──────────────────────────────────────────────────────────
document.querySelectorAll(".mode").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".mode").forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-checked", "false");
    });
    btn.classList.add("active");
    btn.setAttribute("aria-checked", "true");
    state.mode = btn.dataset.mode;
  });
});

// ── Examples ──────────────────────────────────────────────────────────────
document.querySelectorAll(".example").forEach((b) =>
  b.addEventListener("click", () => {
    inputBox.value = b.dataset.ex;
    refreshChip();
    inputBox.focus();
  }),
);

$("#doctorBtn").addEventListener("click", runDoctor);
runBtn.addEventListener("click", () => (state.running ? cancel() : start()));

// ── Timeline ───────────────────────────────────────────────────────────────
const steps = new Map();
function setStep(name, stateName) {
  let li = steps.get(name);
  if (!li) {
    li = el("li");
    li.appendChild(el("span", "dot"));
    li.appendChild(el("span", "label", name));
    timeline.appendChild(li);
    steps.set(name, li);
  }
  li.className = stateName;
}

// ── Rendering ──────────────────────────────────────────────────────────────
function card(opts) {
  const c = el("div", "card" + (opts.err ? " err" : ""));
  if (opts.title || opts.cmd) {
    const head = el("div", "card-head");
    if (opts.cmd) head.appendChild(el("span", "cmd", opts.cmd));
    head.appendChild(el("span", "title", opts.title || ""));
    if (opts.fail) head.appendChild(el("span", "badge-fail", "no result"));
    c.appendChild(head);
  }
  const body = el("div", "card-body");
  c.appendChild(body);
  feed.appendChild(c);
  c.scrollIntoView({ behavior: "smooth", block: "end" });
  return body;
}

// minimal, safe markdown (escape first, then a limited grammar)
function mdToHtml(src) {
  const esc = (t) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const lines = src.split(/\r?\n/);
  let html = "";
  let inList = null;
  const inline = (t) =>
    esc(t)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(?<!\*)\*(?!\*)([^*]+)\*(?!\*)/g, "<em>$1</em>");
  const closeList = () => {
    if (inList) {
      html += `</${inList}>`;
      inList = null;
    }
  };
  for (const raw of lines) {
    const line = raw.trimEnd();
    let m;
    if ((m = line.match(/^(#{1,3})\s+(.*)/))) {
      closeList();
      html += `<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`;
    } else if ((m = line.match(/^\s*[-*]\s+(.*)/))) {
      if (inList !== "ul") {
        closeList();
        html += "<ul>";
        inList = "ul";
      }
      html += `<li>${inline(m[1])}</li>`;
    } else if ((m = line.match(/^\s*\d+\.\s+(.*)/))) {
      if (inList !== "ol") {
        closeList();
        html += "<ol>";
        inList = "ol";
      }
      html += `<li>${inline(m[1])}</li>`;
    } else if (line.trim() === "") {
      closeList();
    } else {
      closeList();
      html += `<p>${inline(line)}</p>`;
    }
  }
  closeList();
  return html;
}

function highlightJson(obj) {
  const json = JSON.stringify(obj, null, 2);
  const esc = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replace(
    /("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let cls = "n";
      if (/^"/.test(match)) cls = /:$/.test(match) ? "k" : "s";
      else if (/true|false|null/.test(match)) cls = "b";
      return `<span class="${cls}">${match}</span>`;
    },
  );
}

// find a screenshot-ish payload in evidence data
function findImage(data) {
  let found = null;
  const walk = (v) => {
    if (found || v == null) return;
    if (typeof v === "string") {
      if (/^data:image\//.test(v)) found = v;
      else if (/^iVBORw0KGgo/.test(v)) found = "data:image/png;base64," + v;
      else if (/^\/9j\//.test(v)) found = "data:image/jpeg;base64," + v;
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(data);
  return found;
}

let assistantBody = null; // accumulate consecutive assistant text into one card

function handleEvent(ev) {
  if (ev.type !== "assistant") assistantBody = null;
  switch (ev.type) {
    case "meta":
      break;
    case "status": {
      const line = el("div", "statusline", ev.text);
      feed.appendChild(line);
      line.scrollIntoView({ behavior: "smooth", block: "end" });
      break;
    }
    case "step":
      setStep(ev.name, ev.state === "run" ? "run" : ev.state === "fail" ? "fail" : "done");
      break;
    case "thinking": {
      const body = card({ title: "" });
      body.parentElement.classList.add("thinking");
      const det = el("details", "thinking");
      const sum = el("summary", null, "reasoning");
      const tb = el("div", "think-body", ev.text);
      det.appendChild(sum);
      det.appendChild(tb);
      body.appendChild(det);
      break;
    }
    case "assistant": {
      if (!assistantBody) assistantBody = card({});
      const chunk = el("div", "assistant");
      chunk.innerHTML = mdToHtml(ev.text);
      assistantBody.appendChild(chunk);
      assistantBody.parentElement.scrollIntoView({ behavior: "smooth", block: "end" });
      break;
    }
    case "evidence": {
      const body = card({ title: ev.title, cmd: ev.command, fail: !ev.ok });
      const img = ev.data ? findImage(ev.data) : null;
      if (img) {
        const image = el("img", "shot");
        image.src = img;
        image.alt = ev.title;
        body.appendChild(image);
      } else if (ev.data != null) {
        const pre = el("pre", "json");
        pre.innerHTML = highlightJson(ev.data);
        body.appendChild(pre);
      } else {
        const pre = el("pre", "json");
        pre.textContent = ev.text || "(no output)";
        body.appendChild(pre);
      }
      break;
    }
    case "error": {
      const body = card({ title: "Error", err: true });
      body.textContent = ev.text;
      break;
    }
    case "done": {
      const line = el("div", "statusline", ev.summary || "done");
      feed.appendChild(line);
      break;
    }
  }
}

// ── Run ──────────────────────────────────────────────────────────────────
async function start() {
  const input = inputBox.value.trim();
  if (!input || state.running) return;
  hint.textContent = "";
  steps.clear();
  timeline.innerHTML = "";
  feed.innerHTML = "";
  assistantBody = null;
  emptyState.hidden = true;
  workspace.hidden = false;
  setRunning(true);
  pushHistory(input);

  state.abort = new AbortController();
  try {
    const res = await api("/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input, mode: state.mode }),
      signal: state.abort.signal,
    });
    if (res.status === 401) {
      setRunning(false);
      return promptToken(start);
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      hint.textContent = err.error || "request failed";
      handleEvent({ type: "error", text: err.error || `HTTP ${res.status}` });
      setRunning(false);
      return;
    }
    await readStream(res.body);
  } catch (e) {
    if (e.name !== "AbortError") handleEvent({ type: "error", text: e.message });
  } finally {
    setRunning(false);
  }
}

async function readStream(stream) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const frame = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const line = frame.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      try {
        const ev = JSON.parse(line.slice(5).trim());
        if (ev.type === "end") return;
        handleEvent(ev);
      } catch {
        /* skip malformed frame */
      }
    }
  }
}

function cancel() {
  state.abort?.abort();
  toast("Run cancelled");
}

function setRunning(on) {
  state.running = on;
  runBtn.disabled = false;
  runBtn.classList.toggle("cancel", on);
  runBtn.querySelector(".run-label").textContent = on ? "Cancel" : "Reverse-engineer";
}

async function runDoctor() {
  toast("Checking engine…");
  try {
    const res = await api("/api/doctor", { method: "POST" });
    if (res.status === 401) return promptToken(runDoctor);
    const d = await res.json();
    emptyState.hidden = true;
    workspace.hidden = false;
    const body = card({ title: "Engine readiness", cmd: "doctor", fail: !d.ok });
    const pre = el("pre", "json");
    if (d.data) pre.innerHTML = highlightJson(d.data);
    else pre.textContent = d.text || "(no output)";
    body.appendChild(pre);
  } catch (e) {
    toast("Engine check failed");
  }
}

// ── History (localStorage) ──────────────────────────────────────────────
function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem("rea.history") || "[]");
  } catch {
    return [];
  }
}
function pushHistory(input) {
  const items = loadHistory().filter((x) => x !== input);
  items.unshift(input);
  localStorage.setItem("rea.history", JSON.stringify(items.slice(0, 20)));
  renderHistory();
}
function renderHistory() {
  const items = loadHistory();
  historyList.innerHTML = "";
  if (!items.length) {
    historyList.appendChild(el("li", "history-empty", "Nothing yet"));
    return;
  }
  for (const item of items) {
    const li = el("li", null, item);
    li.title = item;
    li.addEventListener("click", () => {
      inputBox.value = item;
      refreshChip();
      start();
    });
    historyList.appendChild(li);
  }
}

// ── Token prompt (only when the server requires one) ─────────────────────
function promptToken(retry) {
  const t = window.prompt("This console requires an access token (REA_CONSOLE_TOKEN):", "");
  if (t) {
    state.token = t.trim();
    localStorage.setItem("rea.token", state.token);
    retry?.();
  }
}

// ── Toast ──────────────────────────────────────────────────────────────────
let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  requestAnimationFrame(() => t.classList.add("show"));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => (t.hidden = true), 300);
  }, 2600);
}

// ── Boot ──────────────────────────────────────────────────────────────────
refreshChip();
renderHistory();
health();
