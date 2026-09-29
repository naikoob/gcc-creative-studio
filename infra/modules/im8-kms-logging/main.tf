# Copyright 2026 Google LLC
# IM8 Cryptography (CK-1, CK-2, CK-3, DP-2) & Central Audit Logging (LM-1, LM-2, LM-4, LM-12)

data "google_project" "current" {
  project_id = var.gcp_project_id
}

resource "random_id" "keyring_suffix" {
  byte_length = 3
}

# --- 1. Cloud KMS KeyRing & FIPS 140-3 Level 3 HSM Keys (IM8 CK-1, CK-2, DP-2) ---

resource "google_kms_key_ring" "im8_keyring" {
  name     = "cstudio-im8-${var.environment}-kr-${random_id.keyring_suffix.hex}"
  location = var.gcp_region
  project  = var.gcp_project_id
}

resource "google_kms_crypto_key" "sql_cmek" {
  name            = "cstudio-sql-cmek"
  key_ring        = google_kms_key_ring.im8_keyring.id
  rotation_period = var.key_rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }
}

resource "google_kms_crypto_key" "storage_cmek" {
  name            = "cstudio-storage-cmek"
  key_ring        = google_kms_key_ring.im8_keyring.id
  rotation_period = var.key_rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }
}

resource "google_kms_crypto_key" "artifact_cmek" {
  name            = "cstudio-artifact-cmek"
  key_ring        = google_kms_key_ring.im8_keyring.id
  rotation_period = var.key_rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }
}

# --- 2. Service Agent Identity Provisioning & Least-Privilege KMS Bindings (IM8 CK-3) ---

resource "google_project_service_identity" "sqladmin_agent" {
  provider = google-beta
  project  = var.gcp_project_id
  service  = "sqladmin.googleapis.com"
}

resource "google_project_service_identity" "artifactregistry_agent" {
  provider = google-beta
  project  = var.gcp_project_id
  service  = "artifactregistry.googleapis.com"
}

data "google_storage_project_service_account" "gcs_account" {
  project = var.gcp_project_id
}

resource "google_kms_crypto_key_iam_member" "sql_cmek_binding" {
  crypto_key_id = google_kms_crypto_key.sql_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.sqladmin_agent.email}"
}

resource "google_kms_crypto_key_iam_member" "storage_cmek_binding" {
  crypto_key_id = google_kms_crypto_key.storage_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs_account.email_address}"
}

resource "google_kms_crypto_key_iam_member" "artifact_cmek_binding" {
  crypto_key_id = google_kms_crypto_key.artifact_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.artifactregistry_agent.email}"
}

# --- 3. Comprehensive Cloud Audit Logs (IM8 LM-4, GA-8) ---

resource "google_project_iam_audit_config" "all_services_audit" {
  project = var.gcp_project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# --- 4. Tamper-Resistant 365-Day Audit Log Storage & WOG SIEM Sink (IM8 LM-1, LM-2, LM-12) ---

resource "google_storage_bucket" "immutable_audit_logs" {
  name                        = "${var.gcp_project_id}-cs-${var.environment}-audit-logs"
  project                     = var.gcp_project_id
  location                    = var.gcp_region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.storage_cmek.id
  }

  retention_policy {
    is_locked        = var.lock_audit_bucket
    retention_period = var.audit_log_retention_days * 86400
  }

  depends_on = [google_kms_crypto_key_iam_member.storage_cmek_binding]
}

resource "google_logging_project_sink" "immutable_bucket_sink" {
  name                   = "cstudio-im8-${var.environment}-audit-bucket-sink"
  project                = var.gcp_project_id
  destination            = "storage.googleapis.com/${google_storage_bucket.immutable_audit_logs.name}"
  unique_writer_identity = true

  filter = <<-EOT
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" OR
    logName=~"projects/.+/logs/cloudaudit.googleapis.com%2Fdata_access" OR
    logName=~"projects/.+/logs/cloudsql.googleapis.com%2Fpostgres.log" OR
    resource.type="cloud_run_revision"
  EOT
}

resource "google_storage_bucket_iam_member" "sink_bucket_writer" {
  bucket = google_storage_bucket.immutable_audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.immutable_bucket_sink.writer_identity
}

resource "google_logging_project_sink" "wog_siem_pubsub_sink" {
  count                  = var.wog_siem_pubsub_topic != "" ? 1 : 0
  name                   = "cstudio-im8-${var.environment}-wog-siem-sink"
  project                = var.gcp_project_id
  destination            = var.wog_siem_pubsub_topic
  unique_writer_identity = true

  filter = <<-EOT
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" OR
    logName=~"projects/.+/logs/cloudaudit.googleapis.com%2Fdata_access" OR
    logName=~"projects/.+/logs/cloudsql.googleapis.com%2Fpostgres.log"
  EOT
}
