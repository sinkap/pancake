# Service account that pancake-fleet-server pods run as. Bound via
# Workload Identity to a Kubernetes ServiceAccount in the cluster.
resource "google_service_account" "fleet_server" {
  account_id   = "pancake-fleet-server"
  display_name = "pancake-fleet-server pods"
}

resource "google_project_iam_member" "fleet_server_cloudsql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.fleet_server.email}"
}

resource "google_project_iam_member" "fleet_server_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.fleet_server.email}"
}

# Workload Identity binding: KSA pancake-fleet/fleet-server-sa impersonates
# the GSA. Apply k8s/fleet-server-deployment.yaml's ServiceAccount with
# the iam.gke.io/gcp-service-account annotation matching this email.
resource "google_service_account_iam_member" "fleet_server_wi" {
  service_account_id = google_service_account.fleet_server.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[pancake-fleet/fleet-server-sa]"
}
