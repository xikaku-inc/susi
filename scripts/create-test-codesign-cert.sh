#!/usr/bin/env bash
# Creates a self-signed code-signing certificate for local testing of the
# susi binary-signing feature on macOS.
#
# What this does:
#   1. Generates a 4096-bit RSA key + self-signed certificate with the
#      codeSigning extended key usage.
#   2. Packages them into a PKCS#12 (.p12) file.
#   3. Imports the .p12 into the user's login keychain.
#   4. Marks the certificate as trusted for code signing so that
#      SecStaticCodeCheckValidity accepts it.
#
# Clean up with:  security delete-certificate -c "$CERT_NAME"
#
# Usage:
#   bash scripts/create-test-codesign-cert.sh
#   CERT_NAME="My Org Test" bash scripts/create-test-codesign-cert.sh

set -euo pipefail

CERT_NAME="${CERT_NAME:-Susi Test Code Signing}"
KEYCHAIN="${KEYCHAIN:-$(security list-keychains | grep login | tr -d '[:space:]"')}"
P12_PASS="testpassword"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Working in $WORKDIR"
echo "Target keychain: $KEYCHAIN"

# ---- OpenSSL config for a codeSigning cert ------------------------------
cat > "$WORKDIR/cert.cnf" <<EOF
[req]
distinguished_name = req_dn
x509_extensions    = v3_cs
prompt             = no

[req_dn]
CN = ${CERT_NAME}

[v3_cs]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:true
keyUsage               = critical,digitalSignature,keyCertSign
extendedKeyUsage       = codeSigning
EOF

# ---- Generate key + self-signed cert ------------------------------------
openssl req -x509 \
    -newkey rsa:4096 \
    -keyout "$WORKDIR/key.pem" \
    -out    "$WORKDIR/cert.pem" \
    -days 365 \
    -nodes \
    -config "$WORKDIR/cert.cnf"

echo "Certificate generated."

# ---- Package as PKCS#12 -------------------------------------------------
openssl pkcs12 -export \
    -out     "$WORKDIR/cert.p12" \
    -inkey   "$WORKDIR/key.pem" \
    -in      "$WORKDIR/cert.pem" \
    -passout "pass:$P12_PASS" \
    -legacy

# ---- Import into keychain -----------------------------------------------
security import "$WORKDIR/cert.p12" \
    -P "$P12_PASS" \
    -k "$KEYCHAIN" \
    -T /usr/bin/codesign \
    -T /usr/bin/security

# ---- Trust for code signing ---------------------------------------------
# The cert.pem contains the public cert; we trust it in the keychain.
security add-trusted-cert \
    -d \
    -r trustRoot \
    -k "$KEYCHAIN" \
    "$WORKDIR/cert.pem"

echo ""
echo "Done. Certificate '$CERT_NAME' is trusted for code signing."
echo ""
echo "Sign a binary with:"
echo "  codesign -s '$CERT_NAME' --force <binary>"
echo ""
echo "Verify a signature with:"
echo "  codesign --verify --verbose <binary>"
echo "  spctl -a -v <binary>   # Gatekeeper assessment"
echo ""
echo "Remove the certificate with:"
echo "  security delete-certificate -c '$CERT_NAME'"
