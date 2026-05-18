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

    # Inject dev EK CA root as attestationRoots so step-ca can verify
    # EK cert chains from swtpm. In production with hardware TPMs,
    # replace this with manufacturer roots (Intel/AMD/Infineon).
    HOST_STATE="${PANCAKE_HOST_STATE:-/var/lib/pancake-host-state}"
    EK_CA_ROOT="$HOST_STATE/dev-ek-ca/ca.crt"

    if [ -s "$EK_CA_ROOT" ]; then
        # ACME provisioner's attestationRoots is a []byte in Go (a
        # PEM bundle), which marshals to/from JSON as a base64 string.
        ROOT_B64=$(base64 -w0 < "$EK_CA_ROOT")
        CFG="$CA_HOME/config/ca.json"
        cp "$CFG" "$CFG.bak"
        jq --arg pn "$PROVISIONER_NAME" --arg pem "$ROOT_B64" \
            '(.authority.provisioners[] | select(.name == $pn)) |= (.attestationRoots = $pem))' \
            "$CFG.bak" > "$CFG" 2>&1 || {
            # jq syntax variant for older versions
            jq --arg pn "$PROVISIONER_NAME" --arg pem "$ROOT_B64" \
                '.authority.provisioners |= map(if .name == $pn then .attestationRoots = $pem else . end)' \
                "$CFG.bak" > "$CFG"
        }
        echo "[pancake-ca] injected dev EK CA root as attestationRoots for provisioner '$PROVISIONER_NAME'"
    else
        echo "[pancake-ca] warning: dev EK CA root not found at $EK_CA_ROOT"
        echo "[pancake-ca]   Run init-dev-ek-ca.sh before starting services"
    fi

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

    # Add a JWK provisioner for operator host client certs (first run only).
    # The provisioner addition happens once; trust material publishing
    # is idempotent and happens on every boot (see below).
    HOST_PROVISIONER="${PANCAKE_HOST_PROVISIONER_NAME:-host-cert}"
    HOST_STATE="${PANCAKE_HOST_STATE:-/var/lib/pancake-host-state}"
    HOST_PW="$HOST_STATE/host-cert.jwk.pwd"

    # Wait for bind-mount to become writable, then create JWK password
    if [ -d "$HOST_STATE" ]; then
        for attempt in $(seq 1 10); do
            if mkdir -p "$HOST_STATE" 2>/dev/null && [ -w "$HOST_STATE" ]; then
                break
            fi
            echo "[pancake-ca] waiting for $HOST_STATE to be writable ($attempt/10)"
            sleep 1
        done

        if [ ! -f "$HOST_PW" ]; then
            head -c 32 /dev/urandom | base64 > "$HOST_PW"
            chmod 0600 "$HOST_PW"
        fi

        echo "[pancake-ca] adding JWK provisioner '$HOST_PROVISIONER' (operator host certs)"
        step ca provisioner add "$HOST_PROVISIONER" \
            --type JWK \
            --create \
            --password-file "$HOST_PW" \
            --x509-template "$CA_HOME/templates/server-auth.tpl" \
            --ca-config "$CA_HOME/config/ca.json" \
            2>&1 | sed 's/^/  /' || true
    fi

    FP=$(step certificate fingerprint "$CA_HOME/certs/root_ca.crt")
    echo "[pancake-ca] root fingerprint: $FP"
    echo "[pancake-ca] CA home: $CA_HOME (volume-mount me to persist!)"
fi

# Drop a copy of the root + intermediate cert bundle into the shared
# pancake-trust volume (when mounted) so pancake-build-server can read
# it without HTTPS fetch / operator extraction. Bundle includes both
# root and intermediate so client certs (issued by intermediate) can be
# validated. Idempotent — re-runs every container start so a wiped
# trust volume gets repopulated even on a CA that is already initialized.
if [ -d /pancake-trust ]; then
    cat "$CA_HOME/certs/intermediate_ca.crt" "$CA_HOME/certs/root_ca.crt" > /pancake-trust/trust-root.crt
    echo "[pancake-ca] published trust-root.crt (intermediate + root) to /pancake-trust"

    # Also publish dev EK CA for unified CA mode (local AK cert issuance in VMs)
    HOST_STATE="${PANCAKE_HOST_STATE:-/var/lib/pancake-host-state}"
    if [ -d "$HOST_STATE/dev-ek-ca" ]; then
        mkdir -p /pancake-trust/dev-ek-ca
        cp "$HOST_STATE/dev-ek-ca/ca.crt" /pancake-trust/dev-ek-ca/ 2>/dev/null || true
        cp "$HOST_STATE/dev-ek-ca/ca.key" /pancake-trust/dev-ek-ca/ 2>/dev/null || true
        echo "[pancake-ca] published dev EK CA to /pancake-trust/dev-ek-ca"
    fi
fi

# Publish operator host state to the bind-mount (idempotent, runs every boot).
# Replaces docker exec/cp dance — operator runs `pancake host-cert init`
# which reads these files to mint a client cert without docker exec.
HOST_STATE="${PANCAKE_HOST_STATE:-/var/lib/pancake-host-state}"
HOST_PROVISIONER="${PANCAKE_HOST_PROVISIONER_NAME:-host-cert}"
if [ -d "$HOST_STATE" ]; then
    # Extract and publish the encrypted JWK so operator can sign auth
    # tokens locally. The JWK is encrypted with the password already
    # in $HOST_STATE/host-cert.jwk.pwd. We publish the encryptedKey field,
    # not the public key field.
    jq -r --arg pn "$HOST_PROVISIONER" \
        '.authority.provisioners[] | select(.name == $pn) | .encryptedKey' \
        "$CA_HOME/config/ca.json" > "$HOST_STATE/host-cert.jwk" 2>/dev/null || true
    chmod 0600 "$HOST_STATE/host-cert.jwk" 2>/dev/null || true

    # Publish trust material (intermediate + root bundle for client cert validation)
    cat "$CA_HOME/certs/intermediate_ca.crt" "$CA_HOME/certs/root_ca.crt" > "$HOST_STATE/step-root.crt" 2>/dev/null || true
    chmod 0644 "$HOST_STATE/step-root.crt" 2>/dev/null || true

    # Write service URLs for client defaults
    echo "https://localhost:8443" > "$HOST_STATE/ca-url" 2>/dev/null || true
    echo "localhost:7879" > "$HOST_STATE/builder-addr" 2>/dev/null || true

    # Chown entire dir to operator UID so they can read without sudo
    HOST_UID="${PANCAKE_HOST_UID:-1000}"
    chown -R "$HOST_UID:$HOST_UID" "$HOST_STATE" 2>/dev/null || true

    echo "[pancake-ca] published operator host state to $HOST_STATE"
fi

# Hand off to step-ca. The container already runs as `step` (set
# in Dockerfile), so no su / sudo dance.
exec step-ca --password-file="$CA_HOME/secrets/password" "$CA_HOME/config/ca.json"
