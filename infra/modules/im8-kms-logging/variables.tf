# Copyright 2026 Google LLC
# IM8 Cryptography (CK-1..3, DP-2) & Central Audit Logging (LM-1..4, LM-12) Variables

variable "gcp_project_id" {
  type        = string
  description = "The GCP Project ID."
}

variable "gcp_region" {
  type        = string
  description = "Singapore sovereign region (must be asia-southeast1 per IM8 DP-1)."
  default     = "asia-southeast1"
}

variable "environment" {
  type        = string
  description = "Deployment environment slug (e.g., production)."
  default     = "production"
}

variable "kms_protection_level" {
  type        = string
  description = "Cloud KMS protection level: HSM (FIPS 140-3 Level 3 per IM8 CK-1) or SOFTWARE."
  default     = "HSM"
}

variable "key_rotation_period" {
  type        = string
  description = "Automated key rotation period in seconds (7776000s = 90 days per IM8 CK-2)."
  default     = "7776000s"
}

variable "audit_log_retention_days" {
  type        = number
  description = "Tamper-resistant log retention period in days (minimum 365 days per IM8 LM-2)."
  default     = 365
}

variable "lock_audit_bucket" {
  type        = bool
  description = "Whether to permanently lock the retention policy on the audit log bucket (IM8 LM-2)."
  default     = false
}

variable "wog_siem_pubsub_topic" {
  type        = string
  description = "Optional GovTech WOG GSOC / Jumpgate Pub/Sub topic URI (pubsub.googleapis.com/projects/.../topics/...) for IM8 LM-12 streaming."
  default     = ""
}
