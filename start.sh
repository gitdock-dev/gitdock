#!/bin/bash
# =============================================================================
# start.sh - Start GitDock server and open dashboard (dev mode)
# =============================================================================
# macOS/Linux: run with ./start.sh (or bash start.sh)
# =============================================================================

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  Starting GitDock..."
echo "  Dashboard will open automatically (port may vary if 3847 is busy)"
echo "  Press Ctrl+C to stop."
echo ""

# Open browser after server becomes available (supports port fallback)
(
  base="http://127.0.0.1"
  ports=$(seq 3847 3855)
  attempts=0
  while [ "$attempts" -lt 40 ]; do
    for p in $ports; do
      if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 1 "$base:$p/api/health" >/dev/null 2>&1 && {
          (open "$base:$p" 2>/dev/null || xdg-open "$base:$p" 2>/dev/null) >/dev/null 2>&1
          exit 0
        }
      elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=1 --tries=1 "$base:$p/api/health" -O /dev/null && {
          (open "$base:$p" 2>/dev/null || xdg-open "$base:$p" 2>/dev/null) >/dev/null 2>&1
          exit 0
        }
      else
        # No curl/wget available; fall back to default port
        (open "$base:3847" 2>/dev/null || xdg-open "$base:3847" 2>/dev/null) >/dev/null 2>&1
        exit 0
      fi
    done
    attempts=$((attempts+1))
    sleep 0.5
  done
) &

cd "$BASE_DIR" && node server.js
