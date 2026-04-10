# Signs a binary with the test code-signing certificate created by
# create-test-codesign-cert.ps1.
#
# Usage:
#   .\scripts\sign-binary.ps1 -BinaryPath .\target\debug\my_app.exe
#   .\scripts\sign-binary.ps1 -BinaryPath .\target\debug\my_app.exe -CertName "My Org Test"

param(
    [Parameter(Mandatory)]
    [string]$BinaryPath,
    [string]$CertName = "Susi Test Code Signing"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Locate signtool ----------------------------------------------------
$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Source

if (-not $signtool) {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
    )
    foreach ($pat in $candidates) {
        $found = Get-Item $pat -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { $signtool = $found.FullName; break }
    }
}

if (-not $signtool) {
    Write-Error "signtool.exe not found. Install the Windows SDK (WinSDK optional component in VS installer)."
    exit 1
}

Write-Host "signtool: $signtool"

# ---- Sign ---------------------------------------------------------------
# /fd SHA256  — use SHA-256 as the file digest algorithm
# /n <name>   — pick the cert by subject name from the My store
# No timestamp server: this is a local test cert without network access required.
& $signtool sign /fd SHA256 /n $CertName $BinaryPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool failed (exit $LASTEXITCODE). Is the cert in Cert:\CurrentUser\My?"
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Signed: $BinaryPath"
Write-Host "Verify with: signtool verify /pa /v `"$BinaryPath`""
