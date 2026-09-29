# Copyright 2026 Google LLC
# IM8-Compliant Production Environment Variables (Pattern A)

variable "gcp_project_id" {
  type        = string
  description = "Target GCP Project ID inside the GCC 2.0 compartment."
}

variable "gcp_region" {
  type        = string
  description = "Singapore sovereign region (must be asia-southeast1 per IM8 DP-1)."
  default     = "asia-southeast1"
}

variable "environment" {
  type        = string
  description = "Environment identifier."
  default     = "production"
}

variable "custom_domain" {
  type        = string
  description = "Optional custom agency FQDN bound to the Regional External ALB (e.g., cstudio.agency.gov.sg). When empty, falls back to https://<regional_alb_ip>."
  default     = ""
}

variable "backend_service_name" {
  type        = string
  description = "Name of the backend Cloud Run service."
  default     = "cstudio-be"
}

variable "frontend_service_name" {
  type        = string
  description = "Name of the frontend Cloud Run service."
  default     = "cstudio-fe"
}

variable "db_tier" {
  type        = string
  description = "Cloud SQL machine tier (db-custom-2-7680 recommended for IM8 Production HA; db-custom-1-3840 for Sandbox)."
  default     = "db-custom-2-7680"
}

variable "db_availability_type" {
  type        = string
  description = "Cloud SQL availability type: REGIONAL (mandated for IM8 BR-1) or ZONAL (Sandbox)."
  default     = "REGIONAL"
}

variable "db_name" {
  type        = string
  description = "PostgreSQL database name."
  default     = "creative_studio"
}

variable "kms_protection_level" {
  type        = string
  description = "Cloud KMS key protection level: HSM (FIPS 140-3 Level 3 per IM8 CK-1) or SOFTWARE."
  default     = "HSM"
}

variable "ssl_certificate_pem" {
  type        = string
  description = "PEM-encoded TLS certificate for the Regional External ALB."
  sensitive   = true
}

variable "ssl_private_key_pem" {
  type        = string
  description = "PEM-encoded TLS private key for the Regional External ALB."
  sensitive   = true
}

variable "enforce_sg_geofence" {
  type        = bool
  description = "Restrict inbound ALB traffic strictly to Singapore IP origins."
  default     = false
}

variable "github_conn_name" {
  type        = string
  description = "Cloud Build v2 GitHub host connection name."
  default     = ""
}

variable "github_repo_owner" {
  type        = string
  description = "GitHub repository owner."
  default     = "naikoob"
}

variable "github_repo_name" {
  type        = string
  description = "GitHub repository name."
  default     = "gcc-creative-studio"
}

variable "github_branch_name" {
  type        = string
  description = "Git branch name for automated Cloud Build triggers."
  default     = "im8"
}

variable "google_token_audience" {
  type        = string
  description = "OAuth 2.0 Web Client ID for Google Identity Platform verification."
  default     = ""
}

variable "allowed_orgs" {
  type        = string
  description = "Comma-separated list of permitted Google Workspace / TechPass domains (e.g., tech.gov.sg,moe.gov.sg)."
  default     = ""
}

variable "wog_siem_pubsub_topic" {
  type        = string
  description = "Optional GovTech WOG GSOC / Jumpgate Pub/Sub topic destination for IM8 LM-12 log streaming."
  default     = ""
}

variable "access_policy_id" {
  type        = string
  description = "Optional Organization Access Context Manager Policy ID to provision a VPC Service Controls perimeter (IM8 NS-2, DP-7)."
  default     = ""
}

variable "admin_user_email" {
  type        = string
  description = "Initial administrator email seeded into the Creative Studio database and default workspace."
  default     = "system"
}
