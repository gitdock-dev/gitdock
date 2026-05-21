## Summary

- **Account setup:** Official GitHub `known_hosts` fingerprints, SSH `-T` verification with UI feedback, fine-grained PAT validation, optional **Remember** in the OS credential store (never in `config.json`)
- **Dashboard UX:** **Dormant** repos (renamed from stale), green border on cloned cards, segmented action control bar, modals close on backdrop click and Escape, sidebar Activity log removed
- **Docs and site:** README, privacy, and marketing copy aligned with real token and dormant behavior; Hub **stale** (machines) vs dashboard **dormant** (repos) clarified

## Test plan

- [ ] Add or re-run account setup (SSH verify + token or `gh`)
- [ ] Load repos; check dormant badge and filters
- [ ] Cloned card: green border and control bar actions (Details, Git, Pull, Fetch)
- [ ] Account Manager and other modals close on outside click and Escape
- [ ] Settings shows version **v1.2.0** after bump

## Release

After merge: publish GitHub Release **`v1.2.0`** (CI attaches Windows/macOS/Linux zips). Release notes: `scripts/release-v1.2.0-notes.md`.
