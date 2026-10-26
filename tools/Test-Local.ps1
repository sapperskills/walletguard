# Simple regression runner; does not need network or admin.
$ErrorActionPreference = 'Stop'
Push-Location (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
try {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -m unittest discover -s tests -v
    } else {
        & python -m unittest discover -s tests -v
    }
    if ($LASTEXITCODE -ne 0) { throw 'WalletGuard tests failed.' }
} finally { Pop-Location }
