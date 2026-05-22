## Summary

Adds an OSS-grade automated test suite, CI on `main`, shared `lib/` modules, and contributor docs so we can merge safely without cutting a release for every PR.

## What changed

- **`lib/`** — `security.js`, `git-parse.js`, `dormant.js` (shared with `server.js` and tests)
- **`test/`** — 42 tests: sanitization, git parsers, dormant logic, API integration (isolated temp workspace via `GITDOCK_TEST`)
- **`.github/workflows/test.yml`** — runs `npm test` on push/PR to `main`
- **`server.js`** — imports from `lib/`; test mode; stricter account name validation (rejects names that need character stripping)
- **Docs** — `CHANGELOG.md` (Unreleased), PR template, release policy in `CONTRIBUTING.md`

## Release

**No GitHub Release or version bump.** This is infrastructure and a small security hardening on account names. Binaries stay at v1.2.0 until a future user-visible release (e.g. v1.3.0).

## Test plan

- [x] `npm install && npm test` (42 passing)
- [ ] After merge: confirm GitHub Actions **Tests** workflow is green on `main`
- [ ] Optional: enable branch protection requiring the Tests check
