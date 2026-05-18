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

output "cas_pool_resource_name" {
  description = "Pass to recipe as issuance.cas.pool"
  value       = "projects/${var.project_id}/locations/${var.region}/caPools/${google_privateca_ca_pool.fleet.name}"
}

output "pancake_vm_gsa_email" {
  description = "Service account each Shielded VM should run as (cert requester on the CAS pool)"
  value       = google_service_account.pancake_vm.email
}

output "build_server_internal_ip" {
  description = "Internal IP of the build-server GCE VM; reachable from the GKE fleet-server"
  value       = google_compute_instance.build_server.network_interface[0].network_ip
}

output "build_server_external_ip" {
  description = "External IP of the build-server VM (lock down via firewall in prod)"
  value       = google_compute_instance.build_server.network_interface[0].access_config[0].nat_ip
}
