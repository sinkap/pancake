# Certificate Model

## Implemented: Unified CA Architecture

**Status**: Implemented as of 2026-05-16

**Summary**: Single production CA (step-ca) with dev EK CA mimicking manufacturer roots. Eliminates cross-CA dependencies and simplifies trust model.

### Certificate Authorities

**1. step-ca (pancake-ca-server:8443)** - Production CA
- Root CA with intermediate
- Issues:
  - mTLS client certs for operators (JWK provisioner: `host-cert`)
  - mTLS server certs for VMs (ACME provisioner: `tpm` with device-attest-01 challenge)
  - Code-signing certs for UKI signing (JWK provisioner: `code-sign`)
- attestationRoots: dev EK CA root (validates TPM EK certs during ACME enrollment)

**2. Dev EK CA** - Development TPM manufacturer CA simulator
- Self-signed root CA stored in `pancake-host-state/dev-ek-ca/`
- Signs:
  - swtpm EK certs (during boot-vm.sh via swtpm_setup)
  - VM AK certs (locally in VMs during enrollment)
- Mimics hardware TPM manufacturer CAs (Intel/AMD/Infineon)
- Private key baked into VM images (dev only - production uses hardware TPMs with manufacturer-signed EKs)

### Trust Flows

**VM First Boot (Auto-Enrollment)**
```
1. swtpm starts with EK cert signed by dev EK CA (created by boot-vm.sh)
2. pancake-enroll.service runs:
   a. Creates AK in TPM
   b. Signs AK cert locally using /etc/pancake/orch/dev-ek-ca/ca.key
   c. Performs ACME device-attest-01 with step-ca:
      - Submits TPM attestation with AK cert signed by dev EK CA
      - step-ca validates AK cert chains to attestationRoots (dev EK CA root)
      - Receives mTLS server cert
3. pancaked starts with TPM-resident TLS key + step-ca-issued cert
```

**VM Runtime (pancaked gRPC)**
- Validates operator client certs against: `/etc/pancake/orch/trust-root.crt` (step-ca intermediate + root)
- Serves with: mTLS server cert issued by step-ca (TPM-resident key)

**Operator CLI (orchestrate commands)**
- Validates VM server certs against: `pancake-host-state/step-root.crt` (step-ca intermediate + root)
- Presents: client cert issued by step-ca

### Key Simplifications

1. **Single production CA**: step-ca only. Dev EK CA is dev infrastructure, not a runtime service.
2. **No cross-CA dependencies**: step-ca's attestationRoots points to dev EK CA root, which is static (not another runtime CA).
3. **Clear trust anchors**: 
   - mTLS: step-ca root
   - TPM attestation: dev EK CA root
4. **Standard PKI**: Mimics real-world where TPM manufacturer CAs are separate from enterprise CAs.

### Production Deployment

For hardware TPMs with manufacturer-signed EKs:
1. Replace dev EK CA root with manufacturer roots (Intel/AMD/Infineon) in step-ca's attestationRoots
2. Remove dev EK CA from orch-config layer (VMs don't need to sign their own AK certs)
3. Use manufacturer-issued AK certs or implement proper AK cert enrollment via separate attestation CA

---

# Historical: Previous Dual-CA Architecture

## Original State (Before Unified CA)

### Certificate Authorities

**1. step-ca (pancake-ca-server:8443)**
- Root CA with intermediate
- Issues:
  - Client certs for operators (JWK provisioner: `host-cert`)
  - Server certs for VMs (ACME provisioner: `tpm` with device-attest-01 challenge)
  - Code-signing certs for UKI signing (JWK provisioner: `code-sign`)
- Publishes: intermediate + root bundle to:
  - `/pancake-trust/trust-root.crt` (for build server to bake into VMs)
  - `pancake-host-state/step-root.crt` (for operator CLI)

**2. attest-ca (pancake-attest-ca:8444)**
- Independent CA hierarchy (ca.crt/ca.key)
- Issues: AK (Attestation Key) certificates for TPM 2.0 devices
- Self-signed HTTPS server cert (server.crt/server.key)
- Publishes:
  - `/pancake-trust/attest-ca-ak-root.crt` (ca.crt - for step-ca's attestationRoots)
  - `/pancake-trust/attest-ca-root.crt` (server.crt - for HTTPS validation)
  - `pancake-host-state/attest-ca-root.crt` (server.crt - for operator HTTPS)

### Trust Flows

**VM Enrollment (First Boot)**
```
VM → attest-ca (HTTPS):
  - POST /attest with EK pub + params
  - Receive AK credential encrypted to EK
  - POST /secret with decrypted secret
  - Receive AK cert chain signed by attest-ca's ca.crt

VM → step-ca (HTTPS):
  - ACME device-attest-01 challenge
  - Submit TPM attestation with x5c = [AK cert, attest-ca root]
  - step-ca verifies x5c against attestationRoots (attest-ca's ca.crt)
  - Receive mTLS server cert signed by step-ca intermediate
```

**VM Runtime (pancaked gRPC)**
- Validates operator client certs against: `/etc/pancake/orch/trust-root.crt` (step-ca intermediate + root)
- Serves with: mTLS server cert issued by step-ca

**Operator CLI (orchestrate commands)**
- Validates VM server certs against: `pancake-host-state/step-root.crt` (step-ca intermediate + root)
- Presents: client cert issued by step-ca

### The "Criss Cross" Problem

1. **Cross-CA Dependency**: step-ca's ACME provisioner depends on attest-ca's root (attestationRoots field)
   - step-ca must trust attest-ca to verify TPM attestations
   - Creates coupling between two supposedly independent CAs

2. **Multiple Trust Anchors**:
   - step-ca root (for mTLS client/server certs)
   - attest-ca CA root (for AK certs)
   - attest-ca server cert (for HTTPS, self-signed, unrelated to AK CA)

3. **Confusing Publishing**:
   - 3 different PEM files in /pancake-trust/
   - attest-ca publishes two different certs (ca.crt vs server.crt) with similar names
   - Not obvious which trust material is for what purpose

4. **Bundle Requirements**:
   - VMs need step-ca intermediate + root (not just root) to validate operator client certs
   - Operators need step-ca intermediate + root (not just root) to validate VM server certs
   - Easy to get wrong (original bug: only published root, broke client cert validation)

## Standard PKI Patterns

### Google Production Pattern
- Single root of trust
- Clear hierarchy: Root → Intermediate(s) → Leaves
- Device enrollment uses device-specific CAs but all chain to common root
- No cross-CA dependencies

### Traditional Enterprise PKI
- Root CA (offline, rarely used)
- Issuing CAs (intermediates) for different purposes:
  - User/Client CA
  - Server CA  
  - Device CA
- All intermediates chain to same root
- No CA-to-CA runtime dependencies

## Alternative Designs

### Option A: Single Root, Separate Intermediates

```
Root CA (offline, long-lived)
 ├─ step-ca intermediate (for mTLS client + server certs)
 └─ attest-ca intermediate (for TPM AK certs)
```

**Pros**:
- Single root of trust
- Clear separation of concerns
- No cross-CA dependency (step-ca doesn't need to trust attest-ca root)
- Standard PKI hierarchy

**Cons**:
- Requires generating a separate root CA
- More initial setup complexity
- Need to carefully manage root CA key (offline storage)

**Implementation**:
- Generate root CA once, securely
- Issue intermediate cert to step-ca
- Issue intermediate cert to attest-ca
- step-ca's attestationRoots = attest-ca intermediate (not root)
- All trust bundles just contain root CA cert

### Option B: Unified CA (step-ca Only)

```
step-ca
 ├─ JWK provisioner: host-cert (operator client certs)
 ├─ JWK provisioner: code-sign (UKI signing)
 ├─ ACME provisioner: tpm (VM server certs via device-attest-01)
 └─ Custom TPM AK provisioner (replaces attest-ca entirely)
```

**Pros**:
- Simplest: single CA, single root
- No cross-CA dependencies
- Fewer moving parts

**Cons**:
- step-ca doesn't natively issue TPM AK certs
- Would need to implement custom provisioner or use step-ca's attestation flow differently
- Couples TPM AK issuance to the mTLS CA (less separation of concerns)

**Implementation**:
- Eliminate attest-ca entirely
- Implement TPM AK cert issuance in step-ca
- Single trust root for everything

### Option C: Two Independent CAs (Clean Separation)

```
step-ca: mTLS only
 ├─ JWK provisioner: host-cert (operator client certs)
 ├─ JWK provisioner: code-sign (UKI signing)  
 └─ JWK provisioner: vm-mtls (VM server certs, NO TPM attestation)

attest-ca: TPM attestation only
 └─ Issues AK certs for TPM devices
```

**Pros**:
- Clean separation: mTLS CA vs TPM attestation CA
- No cross-CA dependencies
- Each CA has single clear purpose

**Cons**:
- Loses the benefit of TPM-attested VM enrollment
- VMs get certs via simple JWK flow, not TPM-backed
- Attestation becomes a separate verification step (not baked into cert issuance)

**Implementation**:
- VM bootstrap gets a JWK token baked in, uses it to get server cert from step-ca
- TPM attestation is separate: operator calls `pancake attest`, verifies against attest-ca's root
- Two independent workflows instead of integrated enrollment

### Option D: Current Model with Cleanup

Keep current architecture but fix the confusing parts:

1. **Clearer naming**:
   - `/pancake-trust/step-ca-bundle.crt` (step-ca intermediate + root)
   - `/pancake-trust/attest-ca-ak-root.crt` (attest-ca's CA root for AK certs)
   - `/pancake-trust/attest-ca-tls.crt` (attest-ca's HTTPS server cert)

2. **Single bundle for mTLS**:
   - Both VMs and operators use same step-ca-bundle.crt
   - No confusion about intermediate vs root

3. **Clear documentation**:
   - Trust material flow diagram
   - What validates what against which root

**Pros**:
- Minimal code changes
- Preserves TPM-attested enrollment
- Just fixes naming/documentation confusion

**Cons**:
- Still has cross-CA dependency (step-ca → attest-ca)
- Still has two CA hierarchies
- Doesn't address fundamental architectural concern

## Recommendation

**If keeping TPM-attested enrollment is critical**: Option A (single root, separate intermediates)
- Most aligned with standard PKI practices
- Eliminates confusing cross-CA dependency
- Clear trust model

**If simplicity is priority**: Option B (unified step-ca)
- Fewest moving parts
- Single CA to manage
- Requires custom TPM AK provisioner implementation

**If separating concerns is priority**: Option C (independent CAs)
- Cleanest separation
- TPM attestation becomes runtime verification, not enrollment
- Easier to reason about

**If minimizing changes**: Option D (cleanup current model)
- Fastest to implement
- Fixes confusion without architectural rework
- Leaves cross-CA dependency as-is

## Questions to Resolve

1. How critical is TPM-attested enrollment (device-attest-01) vs runtime attestation?
2. Is managing an offline root CA acceptable complexity?
3. Should TPM AK issuance be coupled to mTLS CA or kept separate?
4. What's the threat model? (affects whether cross-CA dependency matters)
