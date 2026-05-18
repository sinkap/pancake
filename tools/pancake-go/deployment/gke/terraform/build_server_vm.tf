# Privileged GCE VM running pancake-build-server + pancake-sign.
#
# Build is privileged (mmdebstrap, veritysetup, loop devices), which
# fights GKE Autopilot's hardening. A dedicated VM is the pragmatic
# answer: small, gated by SSH, runs the same compose stack as a
# developer machine.
#
# The startup script:
#   1. installs docker + docker-compose-plugin from the official repo
#   2. configures the Artifact Registry helper so it can pull our images
#   3. drops a compose.yaml that runs pancake-build-server + sign-server
#   4. fetches the CAS pool root and Google vTPM roots into the trust
#      volume so bakeOrchConfig can stamp them into orch-config
#
# Operators update the image tag in build_server_image_tag + apply.

resource "google_service_account" "pancake_build" {
  account_id   = "pancake-build-server"
  display_name = "pancake-build-server (privileged GCE)"
}

resource "google_project_iam_member" "build_artifact_pull" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.pancake_build.email}"
}

resource "google_project_iam_member" "build_storage_object_admin" {
  # Bake pipeline uploads built EFI images to the operator's GCS bucket.
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.pancake_build.email}"
}

resource "google_project_iam_member" "build_compute_image_admin" {
  # Optional: bootstrap can create GCE images directly after upload.
  project = var.project_id
  role    = "roles/compute.imageAdmin"
  member  = "serviceAccount:${google_service_account.pancake_build.email}"
}

resource "google_compute_instance" "build_server" {
  name         = "pancake-build-server"
  machine_type = "n2-standard-4"
  zone         = "${var.region}-a"
  tags         = ["pancake-build"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 50
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  network_interface {
    network = "default"
    access_config {} # public IP for image pulls; lock down via firewall in prod
  }

  service_account {
    email  = google_service_account.pancake_build.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  metadata_startup_script = templatefile("${path.module}/build_server_startup.sh.tftpl", {
    region              = var.region
    cas_pool_name       = google_privateca_ca_pool.fleet.name
    build_server_image  = var.build_server_image
    sign_server_image   = var.sign_server_image
    artifact_registry   = "${var.region}-docker.pkg.dev"
  })

  depends_on = [
    google_project_service.required,
    google_privateca_certificate_authority.fleet_root,
  ]
}

# Allow operators to SSH from anywhere (lock this down in prod).
resource "google_compute_firewall" "build_ssh" {
  name    = "pancake-build-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "7879", "7880"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["pancake-build"]
}
