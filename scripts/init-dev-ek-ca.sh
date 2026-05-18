#!/bin/bash
# init-dev-ek-ca.sh: one-time setup for dev EK CA
#
# Generates a root CA that mimics TPM manufacturer CAs (Intel/AMD/Infineon).
# In production, you'd point step-ca's attestationRoots at real manufacturer
# roots. For dev with swtpm, we use this self-signed root to sign swtpm EK
# certs.
#
# Output: pancake-host-state/dev-ek-ca/{ca.crt,ca.key}

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EK_CA_DIR="$SCRIPT_DIR/pancake-host-state/dev-ek-ca"

if [ -f "$EK_CA_DIR/ca.crt" ] && [ -f "$EK_CA_DIR/ca.key" ]; then
    echo "[dev-ek-ca] EK CA already exists at $EK_CA_DIR"
    openssl x509 -in "$EK_CA_DIR/ca.crt" -noout -subject -issuer -dates
    exit 0
fi

echo "[dev-ek-ca] Generating dev EK CA (mimics TPM manufacturer root)"

mkdir -p "$EK_CA_DIR"
chmod 700 "$EK_CA_DIR"

# Generate EC P-256 key for the CA
openssl ecparam -genkey -name prime256v1 -out "$EK_CA_DIR/ca.key"
chmod 600 "$EK_CA_DIR/ca.key"

# Create self-signed root certificate valid for 10 years
# Subject mimics a TPM manufacturer CA
openssl req -new -x509 -sha256 \
    -key "$EK_CA_DIR/ca.key" \
    -out "$EK_CA_DIR/ca.crt" \
    -days 3650 \
    -subj "/C=US/O=pancake-dev/CN=pancake Dev TPM EK CA" \
    -extensions v3_ca \
    -config <(cat <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[ req_distinguished_name ]

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

chmod 644 "$EK_CA_DIR/ca.crt"

echo "[dev-ek-ca] Dev EK CA created:"
echo "  Root cert: $EK_CA_DIR/ca.crt"
echo "  Root key:  $EK_CA_DIR/ca.key (keep secure)"
echo ""
openssl x509 -in "$EK_CA_DIR/ca.crt" -noout -text | grep -A 3 "Subject:"
echo ""
echo "This CA will sign swtpm EK certificates during bootstrap."
echo "step-ca's attestationRoots will point to this CA root."
