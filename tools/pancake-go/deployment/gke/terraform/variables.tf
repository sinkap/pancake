variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for the cluster + Cloud SQL"
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = "pancake-fleet"
}

variable "db_instance_name" {
  description = "Cloud SQL instance name (will be suffixed with random id)"
  type        = string
  default     = "pancake-fleet"
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-g1-small"
}
