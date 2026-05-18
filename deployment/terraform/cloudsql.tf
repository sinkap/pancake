resource "random_id" "db_suffix" {
  byte_length = 3
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "pancake_fleet" {
  name             = "${var.db_instance_name}-${random_id.db_suffix.hex}"
  database_version = "POSTGRES_16"
  region           = var.region

  settings {
    tier                  = var.db_tier
    disk_autoresize       = true
    disk_autoresize_limit = 100
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
    }
    ip_configuration {
      ipv4_enabled = true
      # In production: lock this down to GKE's egress range or use
      # private IP. Left open here to keep the template simple.
    }
  }

  deletion_protection = false

  depends_on = [google_project_service.required]
}

resource "google_sql_database" "pancake_fleet" {
  name     = "pancake_fleet"
  instance = google_sql_database_instance.pancake_fleet.name
}

resource "google_sql_user" "pancake" {
  name     = "pancake"
  instance = google_sql_database_instance.pancake_fleet.name
  password = random_password.db_password.result
}

# Stash the password in Secret Manager so the k8s side can reference it
# without ever putting it on disk.
resource "google_secret_manager_secret" "db_password" {
  secret_id = "pancake-fleet-db-password"
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db_password.result
}
