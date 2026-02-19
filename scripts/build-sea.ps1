# =============================================================================
# build-sea.ps1 - Build GitDock SEA executable (Windows)
# =============================================================================
# Requires: Node.js 22 LTS, npm install (esbuild, postject)
# Run from repo root.
# =============================================================================

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RootDir

Write-Host "  [1/4] Bundling with esbuild..." -ForegroundColor Cyan
npm run build:bundle
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "  [2/4] Generating SEA blob..." -ForegroundColor Cyan
cmd /c "node --experimental-sea-config sea-config.json 2>nul"
$blobPath = Join-Path "dist" "gitdock-sea-prep.blob"
if (-not (Test-Path $blobPath)) {
    Write-Host "  SEA blob was not created." -ForegroundColor Red
    exit 1
}

Write-Host "  [3/4] Copying Node binary and injecting blob..." -ForegroundColor Cyan
$NodePath = (Get-Command node).Source
$ExeOut = "dist\gitdock.exe"
Copy-Item -Path $NodePath -Destination $ExeOut -Force
npx postject $ExeOut NODE_SEA_BLOB dist\gitdock-sea-prep.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
if ($LASTEXITCODE -ne 0) {
    Write-Host "  postject failed. Try: npm install postject --save-dev" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "  [4/4] Done. Executable: $ExeOut" -ForegroundColor Green
Write-Host "  Copy dashboard.html and workspace-setup.html to dist/ and run gitdock.exe from that folder." -ForegroundColor Gray
