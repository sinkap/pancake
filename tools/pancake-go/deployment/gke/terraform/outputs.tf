output "cluster_name" {
  value = google_container_cluster.fleet.name
}

output "cluster_endpoint" {
  value     = google_container_cluster.fleet.endpoint
  sensitive = true
}

output "sql_instance_connection_name" {
  description = "Pass to cloud-sql-proxy as -instances=<this>=tcp:5432"
  value       = google_sql_database_instance.pancake_fleet.connection_name
}

output "sql_db_name" {
  value = google_sql_database.pancake_fleet.name
}

output "sql_user" {
  value = google_sql_user.pancake.name
}

output "db_password_secret" {
  description = "Secret Manager secret id holding the DB password"
  value       = google_secret_manager_secret.db_password.secret_id
}

output "fleet_server_gsa_email" {
  description = "Bind this to the pancake-fleet/fleet-server-sa KSA via Workload Identity"
  value       = google_service_account.fleet_server.email
}
