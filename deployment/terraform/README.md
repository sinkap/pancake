# GKE deployment for pancake-fleet-server

Production-ish deployment of `pancake-fleet-server` on Google Kubernetes
Engine, with Cloud SQL Postgres for persistence. Two layers:

- `terraform/` — provisions the GKE Autopilot cluster, Cloud SQL instance,
  service accounts, and IAM bindings.
- `k8s/` — Kubernetes manifests (Deployment, Service, Ingress, secret
  templates) for running the fleet server on top of the cluster.

The manifests are templates: every `PROJECT_ID`, `REGION`, `INSTANCE_NAME`,
or `EXAMPLE.COM` placeholder must be replaced before `kubectl apply`.

## Quick path

```bash
# 1. Provision infra (one-time)
cd terraform
terraform init
terraform apply -var project_id=YOUR_PROJECT -var region=us-central1

# 2. Connect kubectl to the new cluster
gcloud container clusters get-credentials pancake-fleet \
  --region us-central1 --project YOUR_PROJECT

# 3. Build + push the fleet-server image
gcloud builds submit ../../.. \
  --tag us-central1-docker.pkg.dev/YOUR_PROJECT/pancake/pancake-fleet-server:v1 \
  --config ../../../.cloudbuild/fleet-server.yaml  # or use docker build + push

# 4. Create the namespace and secrets
kubectl apply -f k8s/namespace.yaml
kubectl create secret generic cloudsql-db-credentials \
  -n pancake-fleet \
  --from-literal=connection-string='postgres://pancake:PASSWORD@127.0.0.1:5432/pancake_fleet?sslmode=disable'

kubectl create secret generic cloudsql-sa-key \
  -n pancake-fleet --from-file=service-account.json=key.json

# Optional: mTLS materials to attest pancaked VMs
kubectl create secret generic pancake-mtls -n pancake-fleet \
  --from-file=ca.crt=step-root.crt \
  --from-file=client.crt=client.crt \
  --from-file=client.key=client.key

# 5. Deploy fleet-server
kubectl apply -f k8s/

# 6. Wait for the LoadBalancer IP, point a DNS name at it, configure HTTPS
kubectl get svc pancake-fleet-server -n pancake-fleet -w
```

## Layout

```
deployment/gke/
├── README.md                          # this file
├── terraform/
│   ├── main.tf                        # GKE cluster
│   ├── cloudsql.tf                    # Cloud SQL Postgres
│   ├── networking.tf                  # VPC + firewall
│   ├── iam.tf                         # service accounts + bindings
│   ├── variables.tf
│   └── outputs.tf
└── k8s/
    ├── namespace.yaml
    ├── configmap.yaml                 # non-secret config knobs
    ├── secrets.example.yaml           # template — do not commit real values
    ├── fleet-server-deployment.yaml   # 3-replica Deployment + Cloud SQL Proxy sidecar
    ├── fleet-server-service.yaml      # ClusterIP for HTTP + gRPC
    └── ingress.yaml                   # GKE Ingress + managed cert
```
