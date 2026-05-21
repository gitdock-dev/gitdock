# GitDock v1.2.0 - publish branch, PR, and release helper
# Run from repo root: pwsh -File scripts/publish-v1.2.0.ps1
# Optional: pwsh -File scripts/publish-v1.2.0.ps1 -Push -CreatePr

param(
    [switch]$Push,
    [switch]$CreatePr
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

function Require-GitIdentity {
    $name = git config user.name 2>$null
    $email = git config user.email 2>$null
    if (-not $name -or -not $email) {
        Write-Host "Git user.name / user.email are not set for this repo or globally." -ForegroundColor Red
        Write-Host "Run once (use your GitHub noreply email if you prefer):" -ForegroundColor Yellow
        Write-Host '  git config --global user.name "Your Name"'
        Write-Host '  git config --global user.email "you@users.noreply.github.com"'
        exit 1
    }
}

function Ensure-Branch {
    $branch = git branch --show-current
    if ($branch -ne "feat/v1.2.0-setup-and-dashboard-ux") {
        git checkout -b feat/v1.2.0-setup-and-dashboard-ux 2>$null
        if ($LASTEXITCODE -ne 0) {
            git checkout feat/v1.2.0-setup-and-dashboard-ux
        }
    }
}

Require-GitIdentity
Ensure-Branch

# Reset staging so commits are predictable
git reset HEAD 2>$null | Out-Null

git add server.js dashboard.html
git commit -m @"
feat(app): align account setup with GitHub SSH and token docs

- Use published GitHub SSH host key fingerprints in known_hosts
- SSH verify feedback, fine-grained PAT checks, optional Remember in OS credential store
- Dashboard: dormant repos, cloned border, action control bar, modal backdrop and Escape
- Remove sidebar Activity log
"@

git add README.md site/privacy.html
git commit -m @"
docs: update README and privacy for tokens and dormant repos

- Document PAT session and OS credential store behavior
- Clarify dormant repo detection vs Hub stale machines
- Refresh interface and tech stack sections
"@

git add site/index.html site/download.html
git commit -m @"
docs(site): align marketing copy and security wording

- Replace em dash punctuation in user-facing copy
- Align token and dormant messaging with the app
"@

git add package.json .gitignore scripts/publish-v1.2.0.ps1 scripts/release-v1.2.0-pr-body.md scripts/release-v1.2.0-notes.md
git commit -m @"
chore: release v1.2.0 and publish helper scripts

- Bump package version to 1.2.0
- Ignore persona/ local clone workspace if created inside the repo
- Add scripts to open PR and paste GitHub Release notes
"@

Write-Host "`nCommits on branch feat/v1.2.0-setup-and-dashboard-ux:" -ForegroundColor Green
git log --oneline -4

if ($Push) {
    git push -u origin feat/v1.2.0-setup-and-dashboard-ux
    Write-Host "`nBranch pushed." -ForegroundColor Green
}

if ($CreatePr) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        Write-Host "GitHub CLI (gh) not found. Install gh and run: gh auth login" -ForegroundColor Red
        exit 1
    }
    $bodyFile = Join-Path $PSScriptRoot "release-v1.2.0-pr-body.md"
    gh pr create --base main --head feat/v1.2.0-setup-and-dashboard-ux `
        --title "Release prep: v1.2.0 setup, dashboard UX, and docs" `
        --body-file $bodyFile
    Write-Host "`nPR created. Review and merge on GitHub." -ForegroundColor Green
}

if (-not $Push) {
    Write-Host "`nNext (after reviewing commits):" -ForegroundColor Cyan
    Write-Host "  pwsh -File scripts/publish-v1.2.0.ps1 -Push -CreatePr"
    Write-Host "`nAfter merge, create GitHub Release tag v1.2.0 (see scripts/release-v1.2.0-notes.md)." -ForegroundColor Cyan
}
