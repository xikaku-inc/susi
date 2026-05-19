# Creates a self-signed code-signing certificate for local testing of the
# susi binary-signing feature.
#
# What this does:
#   1. Creates a self-signed certificate with the codeSigning EKU in
#      CurrentUser\My.
#   2. Exports it to a PFX file so signtool can reference it by file.
#   3. Copies the cert into CurrentUser\Root (Trusted Root CAs) so that
#      WinVerifyTrust considers the chain trusted.
#   4. Copies the cert into CurrentUser\TrustedPublisher so that Windows
#      SmartScreen / Authenticode prompts don't block it.
#
# Clean up afterwards with remove-test-codesign-cert.ps1.
#
# Usage:
#   .\scripts\create-test-codesign-cert.ps1
#   .\scripts\create-test-codesign-cert.ps1 -CertName "My Org Test" -PfxPath ".\test.pfx"

param(
    [string]$CertName = "Susi Test Code Signing",
    [string]$PfxPath  = "$PSScriptRoot\test-codesign.pfx",
    [string]$Password = "testpassword"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Create cert --------------------------------------------------------
Write-Host "Creating self-signed code-signing certificate '$CertName'..."
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=$CertName" `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(1)

Write-Host "  Thumbprint : $($cert.Thumbprint)"

# ---- Export to PFX ------------------------------------------------------
$securePass = ConvertTo-SecureString -String $Password -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $securePass | Out-Null
Write-Host "  PFX        : $PfxPath  (password: $Password)"

# ---- Trust: Trusted Root ------------------------------------------------
$rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
$rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$rootStore.Add($cert)
$rootStore.Close()
Write-Host "  Trusted Root: added (WinVerifyTrust will now trust this chain)"

# ---- Trust: Trusted Publishers ------------------------------------------
$pubStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
$pubStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$pubStore.Add($cert)
$pubStore.Close()
Write-Host "  Trusted Publishers: added"

Write-Host ""
Write-Host "Done. Sign a binary with:"
Write-Host "  .\scripts\sign-binary.ps1 -BinaryPath <path>"
Write-Host "Or verify a signature with:"
Write-Host "  signtool verify /pa /v <path>"
Write-Host ""
Write-Host "Remove everything when finished:"
Write-Host "  .\scripts\remove-test-codesign-cert.ps1"
