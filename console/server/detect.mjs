// Classify a free-form target into the engine path that fits it.
import { existsSync, statSync } from "node:fs";
import { extname } from "node:path";
import { homedir } from "node:os";

const GH = /^https?:\/\/(www\.)?github\.com\/([^/\s]+)\/([^/\s#?]+)/i;

const EXT_KIND = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".asar": "javascript",
  ".wasm": "wasm",
  ".wat": "wasm",
  ".apk": "android",
  ".dll": "managed",
  ".exe": "managed",
  ".so": "native",
  ".dylib": "native",
  ".a": "native",
  ".o": "native",
  ".macho": "native",
  ".bin": "native",
  ".ipa": "artifact",
  ".zip": "artifact",
  ".jar": "artifact",
};

function expandHome(p) {
  return p.startsWith("~/") ? p.replace(/^~/, homedir()) : p;
}

/**
 * @param {string} raw
 * @returns {{type:string, input:string, detail?:object, needsAgent?:boolean, label:string}}
 */
export function detectTarget(raw) {
  const input = (raw || "").trim();
  if (!input) return { type: "research", input, label: "Research", needsAgent: true };

  // GitHub repository.
  const gh = input.match(GH);
  if (gh) {
    return {
      type: "github",
      input,
      label: "GitHub repo",
      needsAgent: true, // cloning + reading a repo is an agent-driven flow
      detail: { owner: gh[2], repo: gh[3].replace(/\.git$/, "") },
    };
  }

  // Any other http(s) URL → website.
  if (/^https?:\/\//i.test(input)) {
    let origin = input;
    try {
      origin = new URL(input).origin;
    } catch {
      /* keep raw */
    }
    return { type: "website", input, label: "Website", detail: { origin } };
  }

  // Filesystem path (absolute, home, or relative-looking, or actually exists).
  const looksPath = /^(~\/|\/|\.\/|[a-zA-Z]:[\\/])/.test(input) || existsSync(expandHome(input));
  if (looksPath) {
    const path = expandHome(input);
    let isDir = false;
    try {
      isDir = statSync(path).isDirectory();
    } catch {
      /* may not exist yet; fall through on extension */
    }
    if (isDir) return { type: "javascript", input: path, label: "Local app directory", detail: { path } };
    const kind = EXT_KIND[extname(path).toLowerCase()] || "artifact";
    return { type: kind, input: path, label: `Local ${kind} file`, detail: { path } };
  }

  // 0x-prefixed hex that looks like EVM bytecode.
  if (/^0x[0-9a-fA-F]{8,}$/.test(input)) {
    return { type: "evm", input, label: "EVM bytecode" };
  }

  // Otherwise: natural-language research / "how does X work".
  return { type: "research", input, label: "Research", needsAgent: true };
}
