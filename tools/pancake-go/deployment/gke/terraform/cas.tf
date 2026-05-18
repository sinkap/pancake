# Google Cloud Certificate Authority Service: the CA pool VMs enroll
# their mTLS certs from when the recipe sets `issuance.ca: gcp-cas`.
#
# DevOps tier is the cheap option ($200/month flat) suitable for fleet
# certs. Enterprise tier adds key rotation + per-cert pricing; switch
# when you need it.
#
# This file creates:
#   1. A pool named pancake-fleet
#   2. A single root CA in that pool (root CAs are self-signed; for
#      production you'd typically chain to an external root and put the
#      external root in google-vtpm-roots-style trust bundles)
#   3. IAM bindings:
#        - VMs (gsa_pancake_vm) get roles/privateca.certificateRequester
#          so each Shielded VM can call CreateCertificate via its
#          instance SA
#        - The build-server (gsa_pancake_build) gets
#          roles/privateca.poolReader so it can fetch the pool root
#          cert at bake time

resource "google_privateca_ca_pool" "fleet" {
  name     = "pancake-fleet"
  location = var.region
  tier     = "DEVOPS"

  publishing_options {
    publish_ca_cert = true
    publish_crl     = false # DevOps tier doesn't support CRLs anyway
  }

  depends_on = [google_project_service.required]
}

resource "google_privateca_certificate_authority" "fleet_root" {
  pool                                    = google_privateca_ca_pool.fleet.name
  certificate_authority_id                = "pancake-fleet-root"
  location                                = var.region
  type                                    = "SELF_SIGNED"
  deletion_protection                     = false
  skip_grace_period                       = true
  ignore_active_certificates_on_deletion  = true

  config {
    subject_config {
      subject {
        organization = "pancake"
        common_name  = "pancake fleet root CA"
      }
    }
    x509_config {
      ca_options {
        is_ca = true
      }
      key_usage {
        base_key_usage {
          cert_sign = true
          crl_sign  = true
        }
        extended_key_usage {
          server_auth = true
          client_auth = true
        }
      }
    }
  }

  key_spec {
    algorithm = "EC_P256_SHA256"
  }

  lifetime = "315360000s" # 10 years
}

# Each Shielded VM runs as this SA; the CAS pool trusts it to mint certs.
resource "google_service_account" "pancake_vm" {
  account_id   = "pancake-vm"
  display_name = "pancake Shielded VM runtime (calls CAS for its mTLS cert)"
}

resource "google_privateca_ca_pool_iam_member" "vm_can_request" {
  ca_pool = google_privateca_ca_pool.fleet.id
  role    = "roles/privateca.certificateRequester"
  member  = "serviceAccount:${google_service_account.pancake_vm.email}"
}

# Build-server reads the pool root at bake time to inject into orch-config.
resource "google_privateca_ca_pool_iam_member" "build_server_can_read" {
  ca_pool = google_privateca_ca_pool.fleet.id
  role    = "roles/privateca.poolReader"
  member  = "serviceAccount:${google_service_account.pancake_build.email}"
}
