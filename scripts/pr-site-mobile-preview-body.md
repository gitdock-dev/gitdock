## Summary

Fixes the landing page product preview on mobile: the full dashboard screenshot stays visible at proportional scale, horizontal scroll is removed, and tentacle placement is tuned for small screens without changing desktop layout or image assets.

## Type of change

- [x] Documentation / site only

## What changed

- **`site/index.html`:** `.preview-stage` wrapper; mobile `@media` uses single `zoom` scale (with `transform` fallback); per-tentacle tweaks only where needed (left pair, front pair, right tentacle).
- **`site/css/index.css`:** `.preview-stage` desktop wrapper; removed dead per-tentacle rules that never applied (inline CSS wins); mobile `overflow-x: clip` on preview/html/body.
- **`.gitattributes`:** `text=auto eol=lf` so Windows/Cursor do not flip line endings on every save.

## Release

**No GitHub Release or version bump.** Site-only change (redeploy `site/` when you publish the site).

## Checklist

- [x] Site-only — `npm test` not required for this PR
- [x] Smoke-tested preview at `http://localhost:3848/` (desktop + mobile ~390px)
- [x] No secrets in commits
- [x] Updated `CHANGELOG.md` under **Unreleased**

## Test plan

- [x] Desktop (~1280px): preview matches pre-change layout; tentacles and dashboard unchanged
- [x] Mobile (390px): full dashboard visible, no horizontal scroll
- [x] Tentacles: left pair separated; front pair sized/spaced; right tentacle lower, behind dashboard
- [ ] After deploy: spot-check https://www.gitdock.dev/ on phone or DevTools
