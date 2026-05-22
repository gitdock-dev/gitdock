## Summary

Improves the gitdock.dev download page layout and copy: clearer prerequisites, shorter install flow, centered platform buttons, no redundant Node.js row.

## What changed

- **Download card:** OS buttons (Windows / macOS / Linux) centered
- **Before you start:** moved above install steps; 3-row table (Git, `gh`, SSH); standalone zip note (no Node.js)
- **How to install:** 4 steps per OS; first-run workspace + Add Account only (no repeat of prerequisites)
- **OS warnings:** shorter SmartScreen / Gatekeeper text
- **Why it's safe:** 3 bullets (open source + CI builds, localhost, no tracking)
- Hero clarifies **no GitDock signup** (GitHub setup stays in-app)

## Release

**No GitHub Release or version bump.** Site-only change (redeploy `site/` when you publish the site).

## Test plan

- [x] Open `site/download.html` locally and switch OS tabs
- [ ] After deploy: spot-check https://www.gitdock.dev/download.html
