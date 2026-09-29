# Copyright 2026 Google LLC
# IM8 Cryptography & Audit Logging Module Outputs

output "keyring_id" {
  value       = google_kms_key_ring.im8_keyring.id
  description = "Cloud KMS KeyRing resource ID."
}

output "sql_cmek_id" {
  value       = google_kms_crypto_key.sql_cmek.id
  description = "Cloud KMS CryptoKey ID for Cloud SQL CMEK encryption."
}

output "storage_cmek_id" {
  value       = google_kms_crypto_key.storage_cmek.id
  description = "Cloud KMS CryptoKey ID for Cloud Storage CMEK encryption."
}

output "artifact_cmek_id" {
  value       = google_kms_crypto_key.artifact_cmek.id
  description = "Cloud KMS CryptoKey ID for Artifact Registry CMEK encryption."
}

output "audit_log_bucket_name" {
  value       = google_storage_bucket.immutable_audit_logs.name
  description = "Immutable 365-day audit log bucket name."
}
