#!/usr/bin/env bash
# Launch the REA Console under a REA-supported Node (22.x/24.x/26+).
# Falls back to whatever `node` is on PATH if no pinned version is found.
set -euo pipefail
cd "$(dirname "$0")"

pick_node() {
  for c in \
    /opt/homebrew/opt/node@24/bin/node \
    /opt/homebrew/opt/node@22/bin/node \
    /usr/local/opt/node@24/bin/node \
    /usr/local/opt/node@22/bin/node; do
    [ -x "$c" ] && { echo "$c"; return; }
  done
  command -v node
}

NODE_BIN="$(pick_node)"
echo "Starting REA Console with: $NODE_BIN ($("$NODE_BIN" -v))"
exec "$NODE_BIN" server/index.mjs
