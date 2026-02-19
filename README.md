<p align="center">
  <a href="https://gitdock.dev"><img src="https://img.shields.io/badge/website-gitdock.dev-58a6ff?style=flat-square" alt="Website"></a>
  <img src="https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Node.js-v18+-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js">
  <img src="https://img.shields.io/badge/Express-4.21-000000?style=flat-square&logo=express&logoColor=white" alt="Express">
  <img src="https://img.shields.io/badge/GitHub_CLI-2.0+-24292e?style=flat-square&logo=github&logoColor=white" alt="GitHub CLI">
  <img src="https://img.shields.io/badge/Platform-Windows_%7C_macOS_%7C_Linux-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Network-Localhost_only-green?style=flat-square&logo=shield&logoColor=white" alt="Security">
</p>

<h1 align="center">GitDock</h1>

<p align="center">
  <strong>Open source</strong> local dashboard to manage multiple GitHub accounts in one place.<br>
  View, clone, organize, and operate on dozens of repositories without leaving the browser.
</p>

<p align="center">
  <a href="https://gitdock.dev">Website</a> &middot;
  <a href="https://github.com/gitdock-dev/gitdock/releases">Releases</a> &middot;
  <a href="https://hub.gitdock.dev">Try Hub</a>
</p>

---

## What is this?

GitDock is a **local tool** that runs on your machine and provides a web dashboard to manage repositories from **multiple GitHub accounts** simultaneously.

**It is not a cloud service.** It is not an extension. It is a Node.js server that listens **only on localhost (127.0.0.1)** — no data leaves your machine, no port is exposed to the network.

### Who is it for?

Developers who:
- Have **more than one GitHub account** (professional + personal, for example)
- Manage **dozens or hundreds** of repositories
- Need to clone, pull, commit, push, transfer repos between accounts
- Want to see the status of all projects in one place
- Waste time switching between accounts, terminals, and GitHub tabs

### What it is NOT

- **Does not replace GitHub** — it's a local facilitator
- **Has no database** — uses the GitHub CLI and Git directly
- **Does not send data anywhere** — everything runs on localhost (default `127.0.0.1:3847`; auto-falls back if the port is in use)
- **Does not require a special account** — just an authenticated GitHub CLI

---

## Complete Feature List

### Viewing and Organization

| Feature | Description |
|---|---|
| **Multi-account** | See repos from all accounts in a single dashboard |
| **Informative cards** | Each repo displays: name, owner, description, language, stars, visibility, git status, branch, disk size |
| **Advanced filters** | Filter by account, visibility (public/private), status (cloned/not cloned/stale), sort (updated, A-Z, Z-A, size) |
| **Real-time search** | Search by name, description, language, or username. Shortcut: `/` key |
| **Pinned repos** | Mark favorite repos with ★ — they appear at the top, separated |
| **Custom alias** | Give any repo a nickname to remember what it's about. Opens an elegant modal, saved locally |
| **Stale repo detection** | "stale" badge on repos with no activity for over X months. Configurable threshold: 1, 3, 6, or 12 months |
| **Disk size** | Each card displays the repository size (KB/MB/GB) |
| **Last local commit** | For cloned repos, shows when the last local commit was made |
| **Open PRs and Issues** | Colored pills on the card showing the count of open Pull Requests and Issues (loaded in the background via GraphQL) |
| **Attention panel** | Sidebar lists repos that need attention: uncommitted changes, ahead, behind. Click to navigate directly to the card |
| **Statistics** | Sidebar displays: total repos, cloned, with uncommitted changes, stale |
| **README viewer** | "README" button on each card opens the content rendered in Markdown (local or via GitHub API) |

### Git Operations

| Feature | Description |
|---|---|
| **Clone** | Clone repos with one click. Uses SSH with host aliases for multi-account |
| **Pull** | Pull with safety check — blocks if there are uncommitted changes |
| **Fetch** | Fetch from all remotes without merging |
| **Pull All** | Pull all cloned repos at once |
| **Commit** | Full Git modal: view changed files, select files, write message, commit |
| **Push** | Push directly from the Git modal, with set upstream support |
| **Branch** | View current branch, switch branches, create new branch — all from the modal |
| **Revert** | Revert specific commits directly from the history |
| **Detailed status** | View: branch, changed files with status (modified/added/deleted/untracked), recent commits with hash, and unpushed commit badges |

### Bulk Actions

| Feature | Description |
|---|---|
| **Multi-select** | Checkboxes appear on card hover |
| **Bulk clone** | Select multiple repos and clone them all at once |
| **Bulk pull** | Pull all selected repos |
| **Bulk fetch** | Fetch all selected repos |
| **Action bar** | Fixed bottom bar appears when repos are selected |

### Transfer and Migration

| Feature | Description |
|---|---|
| **Transfer between accounts** | Transfer GitHub repos from one account to another via REST API. Supports asynchronous transfers (requiring email confirmation) |
| **Migrate existing repo** | Move a local repo from any folder into the project's organized structure. Automatically updates the remote URL |

### Editor and Terminal Integration

| Feature | Description |
|---|---|
| **Open in Cursor** | Opens the repo in Cursor via URI scheme (current window) |
| **Open in Cursor (new window)** | Opens in a new Cursor window via CLI |
| **Open in VS Code** | Opens the repo in VS Code via URI scheme (current window) |
| **Open in VS Code (new window)** | Opens in a new VS Code window via CLI |
| **Open Terminal** | Opens a terminal (PowerShell/Terminal.app/xdg-open) in the repo directory |
| **Copy path** | Copies the repo's local path to the clipboard |

### Interface and UX

| Feature | Description |
|---|---|
| **Dark theme** | Dark interface inspired by GitHub Dark |
| **Sidebar + grid layout** | Fixed sidebar with filters and stats, scrollable main area with responsive card grid |
| **Modals** | 7 modals: Alias, Remove, Migrate, Transfer, Confirm Action, README, Git |
| **Toasts** | Temporary notifications (success/error/info) in the top-right corner |
| **Activity log** | Real-time log of all operations in the sidebar |
| **SSE (Server-Sent Events)** | Real-time server updates — connection indicator at the top |
| **⋮ Menu (three dots)** | Context menu on each cloned card with all quick actions |
| **Keyboard shortcuts** | `/` for search, `Escape` to close modals, `Enter` to confirm |
| **Responsive** | Sidebar becomes horizontal on screens smaller than 768px |

---

## Security

The server implements multiple layers of protection:

| Measure | Detail |
|---|---|
| **Localhost only** | Listens exclusively on `127.0.0.1` — inaccessible from the network |
| **IP validation** | Middleware rejects any request not coming from localhost (403) |
| **Body limit** | Requests limited to 10KB (protection against payload abuse) |
| **Input sanitization** | Repo names, branches, commit messages, and hashes are sanitized with strict regex |
| **Path validation** | Paths are normalized and verified against directory traversal (`..`) |
| **Directory confinement** | File operations restricted to the project's base directory |
| **Accidental deletion protection** | Checks for uncommitted changes and unpushed commits before removing |
| **CLI serialization** | Queue ensures `gh` CLI operations don't conflict between accounts |
| **Migration protection** | Blocks migration of sensitive directories (.ssh, AppData, Library, etc.) |
| **Markdown sanitization** | README rendered with DOMPurify to prevent XSS |

---

## Prerequisites

Before installing, you need:

| Tool | Minimum version | Check installation |
|---|---|---|
| **Node.js** | v18+ | `node --version` |
| **npm** | v9+ (comes with Node.js) | `npm --version` |
| **Git** | v2.30+ | `git --version` |
| **GitHub CLI (gh)** | v2.0+ | `gh --version` |
| **SSH** | OpenSSH | `ssh -V` |

### Install prerequisites

#### Windows

```powershell
# Node.js - download from https://nodejs.org (LTS recommended)
# Or via winget:
winget install OpenJS.NodeJS.LTS

# Git
winget install Git.Git

# GitHub CLI
winget install GitHub.cli

# OpenSSH (usually included in Windows 10/11)
# If not installed:
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

#### macOS

```bash
# Node.js
brew install node

# Git (usually comes with Xcode Command Line Tools)
xcode-select --install  # installs git as well
# Or via Homebrew:
brew install git

# GitHub CLI
brew install gh

# SSH is already installed on macOS
```

#### Linux (Ubuntu/Debian)

```bash
# Node.js (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs

# Git
sudo apt-get install -y git

# GitHub CLI
(type -p wget >/dev/null || sudo apt install wget -y) \
  && sudo mkdir -p -m 755 /etc/apt/keyrings \
  && wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
  && sudo apt update \
  && sudo apt install gh -y

# SSH
sudo apt-get install -y openssh-client
```

---

## Step-by-Step Installation

### 1. Clone or create the project

```bash
# Create the project folder
mkdir github-repo-manager
cd github-repo-manager
```

Or clone if you already have the repository:

```bash
git clone git@github.com:YOUR_USER/github-repo-manager.git
cd github-repo-manager
```

### 2. Install dependencies

```bash
npm install
```

This installs only Express (the sole dependency).

### 3. Add accounts via the dashboard

After starting the server (step 7), open the dashboard in your browser. Use **Settings** (or the initial setup flow) to add your GitHub accounts. Each account needs a label, GitHub username, and SSH host alias (e.g. `github.com-work`). Accounts and preferences are stored in `config.json` in your workspace directory.

### 4. Configure SSH for multiple accounts

This is the most important step. SSH allows you to use **two different GitHub accounts** on the same machine without conflict.

#### Option A: Automated script (recommended)

The project includes scripts that do everything automatically:

**Windows (PowerShell as Administrator):**

```powershell
.\scripts\setup-ssh.ps1
```

**macOS / Linux:**

```bash
chmod +x scripts/setup-ssh.sh
./scripts/setup-ssh.sh
```

The script will:
1. Create the `~/.ssh` directory if it doesn't exist
2. Generate Ed25519 SSH keys for each account
3. Configure `~/.ssh/config` with host aliases
4. Add keys to the SSH agent
5. Show the public keys for you to add to GitHub
6. Test the connections

#### Option B: Manual configuration

If you prefer to do it manually:

**Step 4.1 — Generate SSH keys**

```bash
# Key for the professional account
ssh-keygen -t ed25519 -C "professional@github" -f ~/.ssh/id_ed25519_professional

# Key for the personal account
ssh-keygen -t ed25519 -C "personal@github" -f ~/.ssh/id_ed25519_personal
```

When asked for a passphrase, you can leave it blank (Enter) or set a password.

**Step 4.2 — Configure `~/.ssh/config`**

Open (or create) the file `~/.ssh/config`:

**Windows:** `C:\Users\YOUR_USERNAME\.ssh\config`
**macOS/Linux:** `~/.ssh/config`

Add:

```
# Professional account
Host github.com-professional
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_professional
    IdentitiesOnly yes

# Personal account
Host github.com-personal
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_personal
    IdentitiesOnly yes
```

**Step 4.3 — Start the SSH Agent and add keys**

**Windows (PowerShell as Administrator):**

```powershell
# Enable the SSH Agent service
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent

# Add the keys
ssh-add $env:USERPROFILE\.ssh\id_ed25519_professional
ssh-add $env:USERPROFILE\.ssh\id_ed25519_personal
```

**macOS:**

```bash
# Start the agent (usually already running)
eval "$(ssh-agent -s)"

# Add the keys (macOS saves to Keychain)
ssh-add --apple-use-keychain ~/.ssh/id_ed25519_professional
ssh-add --apple-use-keychain ~/.ssh/id_ed25519_personal
```

**Linux:**

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519_professional
ssh-add ~/.ssh/id_ed25519_personal
```

**Step 4.4 — Add public keys to GitHub**

For **each account**, you need to add the corresponding public key:

1. Copy the public key content:

```bash
# Professional
cat ~/.ssh/id_ed25519_professional.pub

# Personal
cat ~/.ssh/id_ed25519_personal.pub
```

**Windows (PowerShell):**

```powershell
# Professional - copy to clipboard
Get-Content $env:USERPROFILE\.ssh\id_ed25519_professional.pub | Set-Clipboard

# Personal - copy to clipboard
Get-Content $env:USERPROFILE\.ssh\id_ed25519_personal.pub | Set-Clipboard
```

2. Log in to GitHub with the **professional account**
3. Go directly to: **https://github.com/settings/keys**
   - Or via the menu: click your **profile picture** (top-right corner) → **Settings** → in the **"Access"** section of the sidebar, click **SSH and GPG keys**
4. Click **New SSH key**
5. In "Title", give it a descriptive name (e.g., "Repo Manager - Professional")
6. In "Key type", select **Authentication Key**
7. In "Key", paste the **professional** public key
8. Click **Add SSH key**
9. **Repeat** for the personal account (log in to the other GitHub account and add the personal key)

**Step 4.5 — Test the connections**

```bash
# Test professional account
ssh -T git@github.com-professional
# Expected: "Hi YOUR-PROF-USER! You've successfully authenticated..."

# Test personal account
ssh -T git@github.com-personal
# Expected: "Hi YOUR-PERSONAL-USER! You've successfully authenticated..."
```

If both return "successfully authenticated", the SSH setup is correct.

### 5. Authenticate the GitHub CLI

The dashboard also uses the `gh` CLI for operations like listing repos and fetching API data. You need to authenticate **both** accounts:

```bash
# Authenticate the first account
gh auth login
# Choose: GitHub.com → HTTPS → Login with a web browser
# Follow the instructions in the browser

# Authenticate the second account
gh auth login
# Repeat the process logged into the other GitHub account
```

Verify that both accounts are authenticated:

```bash
gh auth status
```

Expected:

```
github.com
  ✓ Logged in to github.com account ACCOUNT-1 (keyring)
  ✓ Logged in to github.com account ACCOUNT-2 (keyring)
```

### 6. Create the clone directories

```bash
mkdir professional
mkdir personal
```

These directories will store the local clones of each account's repos.

### 7. Start the server

**Windows:**

```powershell
.\start.ps1
```

**macOS / Linux:**

```bash
chmod +x start.sh
./start.sh
```

**Or directly:**

```bash
node server.js
```

The dashboard opens automatically at: **http://127.0.0.1:3847** (or the next available port if `3847` is already in use).

---

## Project Structure

```
gitdock/
├── server.js                  # Express server (API + security)
├── workspace.js               # Workspace path management (~/.gitdock)
├── dashboard.html             # Web interface (single HTML/CSS/JS file)
├── workspace-setup.html       # First-run workspace picker (packaged build)
├── package.json               # Dependencies (Express only)
├── start.ps1                  # Startup script (Windows)
├── start.sh                   # Startup script (macOS/Linux)
├── LICENSE                    # Apache 2.0
├── CONTRIBUTING.md            # Contribution guide
├── hub/                       # Multi-machine Hub (optional)
│   ├── server.js              # Hub API and dashboard
│   ├── README.md              # Hub setup and deploy
│   └── ...
├── site/                      # Landing page (gitdock.dev)
│   ├── index.html
│   ├── privacy.html
│   └── terms.html
└── <workspace>/                # Your chosen data dir (e.g. ~/GitDock)
    ├── config.json            # Accounts, machine, Hub settings
    ├── account1/               # Clones for account 1
    └── account2/              # Clones for account 2
```

---

## Useful Commands

### Server management

```bash
# Start
node server.js

# Start with auto-reload (development)
npm run dev

# Check if it's running
curl http://127.0.0.1:3847/api/health
```

### GitHub CLI

```bash
# View authenticated accounts
gh auth status

# Switch active account
gh auth switch --user YOUR_USERNAME

# List repos for an account
gh repo list YOUR_USERNAME --limit 200

# Check token permissions
gh auth status -t
```

### SSH

```bash
# Test SSH connection
ssh -T git@github.com-professional
ssh -T git@github.com-personal

# List keys in the agent
ssh-add -l

# Add key to agent
ssh-add ~/.ssh/id_ed25519_professional

# Debug SSH connection (verbose)
ssh -vT git@github.com-professional
```

### Git

```bash
# View remote URL of a repo
cd professional/my-repo
git remote -v

# Change remote URL
git remote set-url origin git@github.com-professional:USER/REPO.git

# View status
git status

# View branches
git branch -a
```

---

## Troubleshooting

### "Server offline" in the dashboard

The server is not running. Start it with `node server.js` or `.\start.ps1` (Windows) / `./start.sh` (macOS/Linux).

### Repos from one account don't show up

**Most likely cause:** The GitHub CLI is not authenticated for that account, or the authentication is incorrect.

```bash
# Check
gh auth status

# Re-authenticate
gh auth login
```

### Clone fails with "Permission denied (publickey)"

The SSH key is not configured correctly.

```bash
# Test
ssh -T git@github.com-professional

# If it fails, check:
# 1. Was the public key added to GitHub?
# 2. Is the SSH agent running?
# 3. Was the key added to the agent?
ssh-add -l  # list keys in the agent
ssh-add ~/.ssh/id_ed25519_professional  # add if needed
```

### "Permission denied" when removing a clone (Windows)

Processes may be locking files. Close editors and terminals that are using the repo, then try again.

### Transfer fails with "Repository has already been taken"

There is a pending transfer for the same repo. Go to GitHub, cancel the pending transfer, and try again.

### Transfer requests email confirmation

Transfers between personal GitHub accounts are **asynchronous** — they require the recipient to accept via email or the GitHub web interface. This is not a bug, it's GitHub's default behavior.

### SSH Agent won't start (Windows)

```powershell
# Run as Administrator
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

### SSH Agent doesn't persist (macOS)

Add to `~/.ssh/config`:

```
Host *
    AddKeysToAgent yes
    UseKeychain yes
```

---

## Customization

### Adding more accounts

Edit the `ACCOUNTS` object in `server.js` to include as many accounts as you want:

```javascript
const ACCOUNTS = {
  professional: {
    githubUser: "account-1",
    sshHost: "github.com-professional",
    localDir: path.join(BASE_DIR, "professional"),
  },
  personal: {
    githubUser: "account-2",
    sshHost: "github.com-personal",
    localDir: path.join(BASE_DIR, "personal"),
  },
  freelance: {  // New account
    githubUser: "account-3",
    sshHost: "github.com-freelance",
    localDir: path.join(BASE_DIR, "freelance"),
  },
};
```

Remember to also:
1. Generate a new SSH key for the account
2. Add the host alias in `~/.ssh/config`
3. Add the public key to GitHub
4. Authenticate in the `gh` CLI
5. Create the local directory (`mkdir freelance`)

### Changing the port

You can set the port using an environment variable:

```bash
GITDOCK_PORT=3847 node server.js
```

Or (Windows PowerShell):

```powershell
$env:GITDOCK_PORT=3847
node server.js
```

If the port is already in use, GitDock will automatically try the next ports.

```javascript
const PORT = 3847;  // Change to your desired port
```

---

## Hub (multi-machine sync)

- **Hosted Hub:** Try it at [hub.gitdock.dev](https://hub.gitdock.dev). Sign up, create an API key in Settings, then in each machine's GitDock dashboard set **Hub URL** to `https://hub.gitdock.dev` and paste the key.
- **Self-host:** The Hub is in the `hub/` folder. Deploy it to [Render](https://render.com) (or any Node host). See [hub/README.md](hub/README.md) for build steps, env vars (`HUB_SECRET`, etc.), and custom domain setup.
- **Local app:** Run `node server.js` as usual; use the dashboard’s **Configure Hub** to point to your Hub URL and API key so this machine sends snapshots.

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style (vanilla JS, no frameworks), and how to submit pull requests and report issues.

---

## Data and Privacy

| Aspect | Detail |
|---|---|
| **Where is data stored?** | Everything is local. Cloned repos in the project folder. Preferences (pins, aliases, filters) in the browser's `localStorage` |
| **What is sent to the internet?** | Only calls to the GitHub API (via `gh` CLI) to list repos, fetch READMEs, and count PRs/Issues. These are the same calls you would make manually |
| **Can anyone access the dashboard?** | No. The server only accepts connections from `127.0.0.1`. No device on your network can access it |
| **Are tokens exposed?** | No. The `gh` CLI manages tokens in the operating system's keyring. The server never touches tokens directly |
| **Can I use it on a corporate network?** | Yes. No port is opened externally. Traffic flows only between the browser and the server, both on your machine |

---

## Tech Stack

- **Backend:** Node.js + Express (single server, ~1100 lines)
- **Frontend:** HTML + CSS + vanilla JavaScript (single file, ~1400 lines, zero frameworks)
- **Git authentication:** SSH with host aliases (Ed25519)
- **GitHub API:** GitHub CLI (`gh`) + REST API + GraphQL API
- **Data:** GitHub CLI for remote repos, Git for local status, `localStorage` for preferences
- **Real-time:** Server-Sent Events (SSE) for asynchronous operations
- **Markdown:** marked.js + DOMPurify for secure README rendering
- **Security:** 10+ layers of protection (see Security section)

---

<p align="center">
  <sub>Built for devs who manage multiple GitHub accounts and want to stop wasting time.</sub>
</p>
