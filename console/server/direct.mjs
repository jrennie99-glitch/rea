// Direct mode — no LLM required. Maps a detected target to a concrete REA
// command plan, runs it, and streams real evidence back to the UI.
import { runRea, runReaStream } from "./rea.mjs";
import { launchForUrl, urlAllowed } from "./browser.mjs";

// A plan is a list of steps; each step is { label, run } where run(emit, ctx)
// returns evidence or throws. ctx carries shared state (e.g. a CDP endpoint).

function evidence(emit, title, command, result) {
  emit({
    type: "evidence",
    title,
    command,
    ok: result.ok,
    data: result.json ?? null,
    text: result.json ? null : result.text?.slice(0, 20000) || result.stderr || "(no output)",
  });
}

async function websitePlan(target, emit) {
  const check = urlAllowed(target.input);
  if (!check.ok) throw new Error(check.reason);

  emit({ type: "step", name: "Launching isolated Chrome", state: "run" });
  const browser = await launchForUrl(target.input, {
    onProgress: (t) => emit({ type: "status", text: t }),
  });
  emit({ type: "step", name: "Launching isolated Chrome", state: "done" });

  try {
    if (!browser.targetId) throw new Error("no page target appeared at the CDP endpoint");
    const ep = browser.endpoint;
    const tid = browser.targetId;

    emit({ type: "step", name: "Inspecting page (CDP)", state: "run" });
    const page = await runRea("inspect-web-page", [
      ep,
      tid,
      "--observation-ms",
      "1500",
      "--include-console-text",
      "--include-json-body-shapes",
    ]);
    evidence(emit, "Page structure, scripts & network", "inspect-web-page", page);
    emit({ type: "step", name: "Inspecting page (CDP)", state: "done" });

    emit({ type: "step", name: "Analysing script bundle", state: "run" });
    const bundle = await runReaStream("analyze-web-bundle", [ep, tid], {
      onProgress: (t) => emit({ type: "status", text: t }),
    });
    evidence(emit, "Bundle: chunks, routes, endpoints & vendor fingerprints", "analyze-web-bundle", bundle);
    emit({ type: "step", name: "Analysing script bundle", state: "done" });

    emit({ type: "step", name: "Capturing screenshot", state: "run" });
    const shot = await runRea("capture-web-screenshot", [ep, tid]);
    evidence(emit, "Viewport screenshot (digested)", "capture-web-screenshot", shot);
    emit({ type: "step", name: "Capturing screenshot", state: "done" });
  } finally {
    browser.close();
  }
}

function singleCommandPlan(target, emit, command, extraArgs = []) {
  return async () => {
    emit({ type: "step", name: command, state: "run" });
    const stream = await runReaStream(command, [target.input, ...extraArgs], {
      onProgress: (t) => emit({ type: "status", text: t }),
    });
    evidence(emit, target.label, command, stream);
    emit({ type: "step", name: command, state: stream.ok ? "done" : "fail" });
    return stream.ok;
  };
}

const COMMAND_BY_TYPE = {
  javascript: "analyze-javascript-application",
  wasm: "inspect-wasm-artifact",
  managed: "inspect-managed-artifact",
  native: "inspect-binary-layout",
  android: "inspect-android-package",
  artifact: "inspect-artifact",
  evm: "inspect-evm-interface",
};

/**
 * Run the direct plan for a target, pushing SSE events through `emit`.
 */
export async function runDirect(target, emit) {
  emit({ type: "status", text: `Direct mode · ${target.label}` });

  if (target.type === "website") {
    await websitePlan(target, emit);
    emit({ type: "done", summary: `Website teardown complete for ${target.detail?.origin || target.input}` });
    return;
  }

  const command = COMMAND_BY_TYPE[target.type];
  if (!command) {
    throw new Error(
      `Direct mode can't handle "${target.type}" targets yet — this needs Agent mode (add an ANTHROPIC_API_KEY).`,
    );
  }
  const ok = await singleCommandPlan(target, emit, command)();

  // Managed binaries: follow up with a member inventory when the artifact read.
  if (target.type === "managed" && ok) {
    await singleCommandPlan(target, emit, "inspect-managed-members")();
  }
  emit({ type: "done", summary: `${target.label} analysis complete` });
}
