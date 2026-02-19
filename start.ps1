# =============================================================================
# start.ps1 - Start GitDock server and open dashboard (dev mode)
# =============================================================================

$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  Starting GitDock..." -ForegroundColor Cyan
Write-Host "  Dashboard will open automatically (port may vary if 3847 is busy)" -ForegroundColor Gray
Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

# Open browser after server becomes available (supports port fallback)
Start-Job -ScriptBlock {
    $base = "http://127.0.0.1"
    $ports = 3847..3855
    $maxAttempts = 40 # ~20s
    for ($i = 0; $i -lt $maxAttempts; $i++) {
        foreach ($p in $ports) {
            try {
                $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 "$base`:$p/api/health"
                if ($r.StatusCode -eq 200) {
                    Start-Process "$base`:$p"
                    return
                }
            } catch { }
        }
        Start-Sleep -Milliseconds 500
    }
} | Out-Null

# Start server
Set-Location $BaseDir
node server.js
