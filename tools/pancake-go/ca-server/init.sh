#!/bin/sh
# pancake-ca-init.sh: first-run bootstrap for the step-ca container.
#
# - On first run, /home/step is empty → run `step ca init` and add an
#   ACME provisioner with the device-attest-01 challenge for TPM 2.0.
# - On subsequent runs, /home/step is populated → just exec step-ca.
#
# Provisioner shape we install:
#   {
#     "type": "ACME",
#     "name": "tpm",
#     "challenges": ["device-attest-01"],
#     "attestationFormats": ["tpm"]
#   }
#
# Without `attestationRoots`, step-ca uses per-device EK pubkey
# allowlisting via the permanent-identifier extension. The
# orchestrator drops authorized EKs in via `pancake ca-server
# enroll-device` (step-ca admin API). Production deployments with
# hardware TPMs should set attestationRoots to the TPM
# manufacturer roots (Intel/Infineon/AMD).

set -eu

CA_HOME=/home/step
CA_DNS="${PANCAKE_CA_DNS:-localhost,127.0.0.1}"
CA_NAME="${PANCAKE_CA_NAME:-pancake-ca}"
CA_LISTEN="${PANCAKE_CA_LISTEN:-:8443}"
PROVISIONER_NAME="${PANCAKE_PROVISIONER_NAME:-tpm}"

if [ ! -f "$CA_HOME/config/ca.json" ]; then
    echo "[pancake-ca] first run — bootstrapping CA"

    # Random password protects both the root CA key and the
    # provisioner JWK. Stashed inside the volume so subsequent
    # operations can read it. Operators rotating this must also
    # rotate the keys it protects.
    PWFILE="$CA_HOME/secrets/password"
    mkdir -p "$CA_HOME/secrets"
    if [ ! -f "$PWFILE" ]; then
        head -c 32 /dev/urandom | base64 > "$PWFILE"
        chmod 0600 "$PWFILE"
    fi

    # Bootstrap. step ca init mints root + intermediate, writes
    # config/ca.json with a JWK provisioner. We deliberately skip
    # --remote-management — that mode stores provisioners in the
    # badger DB and ignores ca.json's `provisioners` block once
    # step-ca is running. We want ca.json to be authoritative so
    # subsequent `step ca provisioner update --ca-config` calls
    # (which edit the file in place) take effect after a SIGHUP.
    step ca init \
        --name "$CA_NAME" \
        --dns "$CA_DNS" \
        --address "$CA_LISTEN" \
        --provisioner pancake-admin \
        --password-file "$PWFILE" \
        --provisioner-password-file "$PWFILE" \
        2>&1 | sed 's/^/  /'

    # X.509 template that adds ServerAuth EKU to issued certs.
    # Default ACME templates omit EKU; strict TLS clients (openssl,
    # gRPC-Go in some configs) reject server certs without it.
    cat > "$CA_HOME/templates/server-auth.tpl" <<'TPL'
{
    "subject": {{ toJson .Subject }},
    "sans": {{ toJson .SANs }},
    "keyUsage": ["digitalSignature", "keyEncipherment"],
    "extKeyUsage": ["serverAuth", "clientAuth"]
}
TPL

    # X.509 template for the pancake-sign service's code-signing
    # leaf cert. EKU=codeSigning is what UEFI Secure Boot's `db`
    # check looks for on a signed UKI's leaf. KeyUsage drops
    # keyEncipherment (signing-only) and adds digitalSignature.
    cat > "$CA_HOME/templates/code-sign.tpl" <<'TPL'
{
    "subject": {{ toJson .Subject }},
    "sans": {{ toJson .SANs }},
    "keyUsage": ["digitalSignature"],
    "extKeyUsage": ["codeSigning"]
}
TPL

    # Add the ACME-tpm provisioner. `step ca provisioner add` writes
    # straight to the on-disk ca.json since the daemon isn't running
    # yet.
    echo "[pancake-ca] adding ACME provisioner '$PROVISIONER_NAME' (device-attest-01 / tpm)"
    step ca provisioner add "$PROVISIONER_NAME" \
        --type ACME \
        --challenge device-attest-01 \
        --attestation-format tpm \
        --x509-template "$CA_HOME/templates/server-auth.tpl" \
        --ca-config "$CA_HOME/config/ca.json" \
        2>&1 | sed 's/^/  /'

    # Add a JWK provisioner for the code-signing flow. pancake-sign
    # uses this provisioner (one-shot CSR with the JWK key) to mint
    # its leaf cert chained to step-ca's root. Operators enroll
    # step-ca's root in UEFI db once → any leaf this provisioner
    # issues can sign UKIs that boot.
    SIGN_PROVISIONER="${PANCAKE_SIGN_PROVISIONER_NAME:-code-sign}"
    echo "[pancake-ca] adding JWK provisioner '$SIGN_PROVISIONER' (code-signing leaves)"
    step ca provisioner add "$SIGN_PROVISIONER" \
        --type JWK \
        --create \
        --password-file "$PWFILE" \
        --x509-template "$CA_HOME/templates/code-sign.tpl" \
        --ca-config "$CA_HOME/config/ca.json" \
        2>&1 | sed 's/^/  /' || true

    FP=$(step certificate fingerprint "$CA_HOME/certs/root_ca.crt")
    echo "[pancake-ca] root fingerprint: $FP"
    echo "[pancake-ca] CA home: $CA_HOME (volume-mount me to persist!)"
fi

# Drop a copy of the root cert into the shared pancake-trust volume
# (when mounted) so pancake-build-server can read it without HTTPS
# fetch / operator extraction. Idempotent — re-runs every container
# start so a wiped trust volume gets repopulated even on a CA that
# is already initialized.
if [ -d /pancake-trust ]; then
    install -m 0644 "$CA_HOME/certs/root_ca.crt" /pancake-trust/trust-root.crt
    echo "[pancake-ca] published trust-root.crt to /pancake-trust"
fi

# Hand off to step-ca. The container already runs as `step` (set
# in Dockerfile), so no su / sudo dance.
exec step-ca --password-file="$CA_HOME/secrets/password" "$CA_HOME/config/ca.json"
