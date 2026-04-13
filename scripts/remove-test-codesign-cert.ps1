# Removes the test code-signing certificate from all stores it was added to
# by create-test-codesign-cert.ps1.
#
# Usage:
#   .\scripts\remove-test-codesign-cert.ps1
#   .\scripts\remove-test-codesign-cert.ps1 -CertName "My Org Test"

param(
    [string]$CertName = "Susi Test Code Signing",
    [string]$PfxPath  = "$PSScriptRoot\test-codesign.pfx"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$storeNames = @(
    [System.Security.Cryptography.X509Certificates.StoreName]::My,
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher
)

foreach ($storeName in $storeNames) {
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        $storeName,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $certs = $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindBySubjectName,
        $CertName, $false)
    foreach ($c in $certs) {
        $store.Remove($c)
        Write-Host "Removed from $storeName : $($c.Thumbprint)"
    }
    $store.Close()
}

if (Test-Path $PfxPath) {
    Remove-Item $PfxPath
    Write-Host "Deleted: $PfxPath"
}

Write-Host "Done."
