terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "required" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "privateca.googleapis.com",
    "storage.googleapis.com",
    "artifactregistry.googleapis.com",
  ])
  service            = each.key
  disable_on_destroy = false
}

# GKE Autopilot cluster — Google manages the nodes, we just declare pods.
# Smaller surface area for production; perfect fit for a small fleet server.
resource "google_container_cluster" "fleet" {
  name     = var.cluster_name
  location = var.region

  enable_autopilot = true

  # Workload Identity is on by default in Autopilot; explicit here for
  # clarity. fleet-server pods bind to a GSA via this mechanism, which
  # lets the Cloud SQL Proxy authenticate without a key.json.
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  release_channel {
    channel = "REGULAR"
  }

  ip_allocation_policy {}

  depends_on = [google_project_service.required]
}
