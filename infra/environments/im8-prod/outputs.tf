# Copyright 2026 Google LLC
# IM8-Compliant Production Environment Outputs

output "regional_alb_ip" {
  value       = module.im8_network_alb.regional_alb_ip
  description = "Regional External ALB static IPv4 address (asia-southeast1 Standard Tier)."
}

output "regional_alb_origin" {
  value       = local.alb_origin
  description = "Unified HTTPS origin URL fronting both Angular SPA (/*) and FastAPI (/api/*)."
}

output "cloud_sql_connection_name" {
  value       = google_sql_database_instance.im8_postgres.connection_name
  description = "Cloud SQL PostgreSQL 18 instance connection name."
}

output "cloud_sql_private_ip" {
  value       = google_sql_database_instance.im8_postgres.private_ip_address
  description = "Private VPC IPv4 address of the Cloud SQL instance."
}

output "genmedia_bucket_name" {
  value       = google_storage_bucket.genmedia.name
  description = "CMEK-encrypted GenMedia Cloud Storage bucket."
}

output "audit_log_bucket_name" {
  value       = module.im8_kms_logging.audit_log_bucket_name
  description = "Immutable 365-day retention-locked Cloud Audit Logs bucket."
}

output "backend_repo_name" {
  value       = google_artifact_registry_repository.be_repo.name
  description = "Backend Artifact Registry repository name."
}

output "frontend_repo_name" {
  value       = google_artifact_registry_repository.fe_repo.name
  description = "Frontend Artifact Registry repository name."
}
