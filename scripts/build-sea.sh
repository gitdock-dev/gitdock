#!/usr/bin/env bash
# =============================================================================
# build-sea.sh - Build GitDock SEA executable (macOS / Linux)
# =============================================================================
# Requires: Node.js 22 LTS, npm install (esbuild, postject)
# Run from repo root: ./scripts/build-sea.sh
# =============================================================================

set -e
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "  [1/5] Bundling with esbuild..."
npm run build:bundle

echo "  [2/5] Generating SEA blob..."
node --experimental-sea-config sea-config.json 2>/dev/null || true
if [ ! -f "dist/gitdock-sea-prep.blob" ]; then
  echo "  SEA blob was not created."
  exit 1
fi

echo "  [3/5] Copying Node binary..."
NODE_PATH="$(command -v node)"
EXE_OUT="dist/gitdock"
cp "$NODE_PATH" "$EXE_OUT"

if [ "$(uname -s)" = "Darwin" ]; then
  echo "  [4/5] Removing macOS signature..."
  codesign --remove-signature "$EXE_OUT" 2>/dev/null || true
fi

echo "  [5/5] Injecting SEA blob..."
npx postject "$EXE_OUT" NODE_SEA_BLOB dist/gitdock-sea-prep.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2

if [ "$(uname -s)" = "Darwin" ]; then
  echo "  Re-signing..."
  codesign --sign - "$EXE_OUT"
fi

echo "  Done. Executable: $EXE_OUT"
echo "  Copy dashboard.html and workspace-setup.html to dist/ and run ./gitdock from that folder."
