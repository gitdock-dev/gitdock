## What's new

### Account setup
- Setup timeline aligned with [GitHub SSH](https://docs.github.com/en/authentication/connecting-to-github-with-ssh) docs (published host key fingerprints, `ssh -T` verify)
- Fine-grained PAT with **Contents** read (and optional **Git SSH keys** for upload-via-API)
- Optional **Remember** stores PAT in your OS credential store (Windows Credential Manager, macOS Keychain, or Linux Secret Service). Never written to `config.json`

### Dashboard UX
- **Dormant** badge and filter for repos with no recent activity (last local commit if cloned, otherwise GitHub `updated_at`)
- Cloned repos: subtle green border for quick scanning
- Repo actions grouped in one control bar per card
- Modals close when clicking outside or pressing Escape
- Removed sidebar Activity log (toasts and SSE remain)

### Docs
- README and site copy updated for tokens, dormant repos, and Hub terminology

## Upgrade notes

- Existing accounts: open **Manage Accounts → Setup Status** if SSH or API steps need a re-check
- Download a build below or run from source: `git pull`, `npm install`, `npm start`
