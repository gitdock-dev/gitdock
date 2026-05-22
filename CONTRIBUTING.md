# Contributing to GitDock

Thank you for your interest in contributing to GitDock. This document explains how to set up the project, our code style, and how to submit changes.

## Code of conduct

Be respectful and constructive. We aim to keep the community welcoming and focused on building a useful tool for developers.

## Development setup

### Prerequisites

- **Node.js** v18 or later
- **Git** v2.30+
- **GitHub CLI (gh)** v2.0+ (for API and auth)
- **SSH** (OpenSSH) for Git operations

### Clone and run

```bash
git clone https://github.com/gitdock-dev/gitdock.git
cd gitdock
npm install
npm start
```

The dashboard will be available at **http://127.0.0.1:3847**. To run with auto-reload during development:

```bash
npm run dev
```

### Hub (optional)

To work on the multi-machine Hub:

```bash
cd hub
cp .env.example .env
# Set HUB_SECRET (min 32 chars) and optionally HUB_DB_KEY
npm install
npm start
```

Hub runs at **http://localhost:3848** by default.

## Testing

GitDock uses the Node.js built-in test runner (`node --test`) plus [supertest](https://github.com/ladjs/supertest) for HTTP checks.

| Command | What it runs |
|---------|----------------|
| `npm test` | Full suite (security, git parsers, dormant logic, API integration) |
| `npm run test:unit` | Pure library tests only (no server) |
| `npm run test:api` | Express API integration tests in an isolated temp workspace |

Tests live under `test/`. Shared validation logic is in `lib/` so the server and tests stay aligned.

Before opening a PR, run `npm test` and ensure it passes.

## Releases and versioning

We use [Semantic Versioning](https://semver.org/). Not every merged PR becomes a GitHub Release.

| Change type | Version bump | GitHub Release (binaries) |
|-------------|--------------|---------------------------|
| Bug fix users depend on | Patch (e.g. 1.2.1) | Yes, when the fix matters for downloaded builds |
| New UX or API behavior | Minor (e.g. 1.3.0) | Yes, when bundling several user-visible changes |
| Tests, CI, docs, refactors | None required | No |

Track user-facing work in [CHANGELOG.md](CHANGELOG.md) under **Unreleased**. When cutting a release, move items to a version section, bump `package.json`, tag `vX.Y.Z`, and publish the release (that triggers the build workflow).

## Code style

- **Language:** All code and comments in English.
- **Backend:** Vanilla Node.js and Express. No TypeScript or extra frameworks in the core app.
- **Frontend:** Vanilla HTML, CSS, and JavaScript. No React, Vue, or other frameworks in the dashboard or landing page.
- **Formatting:** Use consistent indentation (spaces). Keep lines readable (avoid very long lines).
- **Security:** Do not add arbitrary command execution, and do not expose sensitive data. Paths and inputs must be validated and sanitized.

## Submitting changes

1. **Fork** the repository and create a branch from `main` (e.g. `feat/your-feature` or `fix/issue-description`).
2. **Make your changes** and run the automated suite: `npm test` (unit + API integration). Also smoke-test the dashboard when UI changes: `npm start`.
3. **Commit** with clear messages (e.g. `feat: add X`, `fix: resolve Y`).
4. **Push** to your fork and open a **Pull Request** against `gitdock-dev/gitdock` `main`.
5. Describe what you changed and why. Reference any related issues.

## Issues

- Use **Issues** for bugs, feature ideas, or documentation improvements.
- Search existing issues first to avoid duplicates.
- For bugs, include steps to reproduce, your OS, and Node version when relevant.

## Questions

- Open an issue with the "question" label, or contact the maintainers via the email on the project homepage.

Thank you for contributing.
