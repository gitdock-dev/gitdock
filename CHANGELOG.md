# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Automated test suite (`npm test`) using Node.js built-in test runner and supertest.
- Shared libraries under `lib/` for security validation, git status parsing, and dormant repo logic.
- GitHub Actions workflow to run tests on push and pull requests to `main`.
- `CHANGELOG.md`, pull request template, and release policy in `CONTRIBUTING.md`.

### Changed

- `server.js` imports validation helpers from `lib/` (behavior preserved; easier to test).
- Account name validation now rejects names that require stripping unsafe characters (e.g. `bad name!`, `work;rm`).

### Security

- Stricter `sanitizeAccountName` so shell-like input cannot be silently normalized into a valid account id.

## [1.2.0] - 2026-05-21

### Added

- Five-step account setup with GitHub-aligned SSH and fine-grained PAT guidance.
- Optional token storage in the OS credential store (not in `config.json`).
- Official GitHub `known_hosts` fingerprints and SSH verify feedback in setup status.
- Dormant repo filter and terminology (replaces stale/inactive).
- Modal close on outside click and Escape; segmented repo action bar; cloned repo green border.

### Changed

- Activity Log removed; feedback via toasts and SSE.
- README, privacy page, and site copy aligned with real token and dormant behavior.

[Unreleased]: https://github.com/gitdock-dev/gitdock/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/gitdock-dev/gitdock/releases/tag/v1.2.0
