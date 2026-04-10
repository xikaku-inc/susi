# Builds the susi_server integration tests, signs the test binary with the
# test code-signing certificate, then runs the tests.
#
# This is necessary for the test_require_signed_binary_enforcement test to
# exercise the Valid (signed) path. Without signing, that test will observe
# UnsignedBinary, which is also correct behaviour and tested separately.
#
# Prerequisites:
#   1. Run .\scripts\create-test-codesign-cert.ps1 once.
#   2. Have signtool.exe in PATH or Windows SDK installed.
#
# Usage:
#   .\scripts\sign-and-test.ps1
#   .\scripts\sign-and-test.ps1 -Filter test_require_signed_binary

param(
    [string]$CertName = "Susi Test Code Signing",
    [string]$Filter   = ""          # passed to -- --test-threads / --nocapture etc.
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Build tests (no run) -----------------------------------------------
Write-Host "Building integration tests..."
$buildOutput = cargo test --no-run --test integration --message-format=json 2>&1

# Parse JSON lines to find the test executable
$testBinary = $buildOutput |
    ForEach-Object { try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { $null } } |
    Where-Object { $_ -and $_.reason -eq "compiler-artifact" -and $_.target.test -eq $true } |
    Select-Object -ExpandProperty executable -Last 1

if (-not $testBinary) {
    # Fallback: newest integration-*.exe in target/debug/deps
    $testBinary = Get-ChildItem "target\debug\deps\integration*.exe" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -ExpandProperty FullName -First 1
}

if (-not $testBinary) {
    Write-Error "Could not locate the integration test binary. Run 'cargo build --tests' first."
    exit 1
}

Write-Host "Test binary: $testBinary"

# ---- Sign ---------------------------------------------------------------
Write-Host "Signing..."
& "$PSScriptRoot\sign-binary.ps1" -BinaryPath $testBinary -CertName $CertName

# ---- Run ----------------------------------------------------------------
Write-Host ""
Write-Host "Running integration tests..."
$runArgs = @($testBinary)
if ($Filter) { $runArgs += $Filter }

& $testBinary @runArgs
exit $LASTEXITCODE
