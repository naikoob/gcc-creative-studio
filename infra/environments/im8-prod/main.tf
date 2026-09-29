# Copyright 2026 Google LLC
# IM8-Compliant Production Environment (Pattern A: Regional ALB + Cloud Run FE/BE)
# Leaves upstream infra/modules/ untouched for zero-conflict upstream merges.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google      = { source = "hashicorp/google" }
    google-beta = { source = "hashicorp/google-beta" }
    random      = { source = "hashicorp/random" }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "google-beta" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

locals {
  apis_to_enable = [
    "serviceusage.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudkms.googleapis.com",
    "sqladmin.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "secretmanager.googleapis.com",
    "aiplatform.googleapis.com",
    "workflows.googleapis.com",
    "iamcredentials.googleapis.com",
    "texttospeech.googleapis.com",
    "dlp.googleapis.com",
    "certificatemanager.googleapis.com",
  ]

  alb_origin  = var.custom_domain != "" ? "https://${var.custom_domain}" : "https://${module.im8_network_alb.regional_alb_ip}"
  iam_db_user = trimsuffix(google_service_account.be_run_sa.email, ".gserviceaccount.com")
}

resource "google_project_service" "apis" {
  for_each           = toset(local.apis_to_enable)
  project            = var.gcp_project_id
  service            = each.key
  disable_on_destroy = false
}

# ==============================================================================
# 1. IM8 Cryptography (CMEK HSM) & 365-Day Immutable Audit Logging
# ==============================================================================
module "im8_kms_logging" {
  source = "../../modules/im8-kms-logging"

  gcp_project_id        = var.gcp_project_id
  gcp_region            = var.gcp_region
  environment           = var.environment
  kms_protection_level  = var.kms_protection_level
  wog_siem_pubsub_topic = var.wog_siem_pubsub_topic

  depends_on = [google_project_service.apis]
}

# ==============================================================================
# 2. IM8 Sovereign VPC, Cloud NAT, Regional Cloud Armor WAF & Regional External ALB
# ==============================================================================
module "im8_network_alb" {
  source = "../../modules/im8-network-alb"

  gcp_project_id        = var.gcp_project_id
  gcp_region            = var.gcp_region
  environment           = var.environment
  custom_domain         = var.custom_domain
  backend_service_name  = var.backend_service_name
  frontend_service_name = var.frontend_service_name
  ssl_certificate_pem   = file(startswith(var.ssl_certificate_path, "/") ? var.ssl_certificate_path : "${path.module}/${var.ssl_certificate_path}")
  ssl_private_key_pem   = file(startswith(var.ssl_private_key_path, "/") ? var.ssl_private_key_path : "${path.module}/${var.ssl_private_key_path}")
  enforce_sg_geofence   = var.enforce_sg_geofence

  depends_on = [google_project_service.apis]
}

# ==============================================================================
# 3. Hardened GenMedia Cloud Storage Bucket (IM8 DP-1, DP-2, ST-1, AS-8, BR-1)
# ==============================================================================
resource "google_storage_bucket" "genmedia" {
  name                        = "${var.gcp_project_id}-cs-${var.environment}-bucket"
  project                     = var.gcp_project_id
  location                    = var.gcp_region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = module.im8_kms_logging.storage_cmek_id
  }

  versioning {
    enabled = true
  }

  cors {
    origin          = [local.alb_origin]
    method          = ["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS"]
    response_header = ["Content-Type", "Access-Control-Allow-Origin", "x-goog-resumable", "Authorization", "Origin"]
    max_age_seconds = 3600
  }

  depends_on = [module.im8_kms_logging]
}

resource "google_service_account" "bucket_reader_sa" {
  project      = var.gcp_project_id
  account_id   = "cs-${var.environment}-read"
  display_name = "SA for reading/signing GenMedia (${var.environment}) bucket"
}

resource "google_storage_bucket_iam_member" "bucket_viewer_binding" {
  bucket = google_storage_bucket.genmedia.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.bucket_reader_sa.email}"
}

resource "google_storage_bucket_iam_member" "bucket_creator_binding" {
  bucket = google_storage_bucket.genmedia.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.bucket_reader_sa.email}"
}

# ==============================================================================
# 4. Private Regional HA Cloud SQL PostgreSQL 18 (IM8 DP-2, DP-3, NS-1, BR-1, LM-4)
# ==============================================================================
resource "random_id" "db_name_suffix" {
  byte_length = 4
}

resource "google_sql_database_instance" "im8_postgres" {
  name                = "creative-studio-im8-${random_id.db_name_suffix.hex}"
  database_version    = "POSTGRES_18"
  region              = var.gcp_region
  project             = var.gcp_project_id
  encryption_key_name = module.im8_kms_logging.sql_cmek_id
  deletion_protection = true

  settings {
    tier              = var.db_tier
    availability_type = var.db_availability_type
    disk_autoresize   = true

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }

    database_flags {
      name  = "pgaudit.log"
      value = "all"
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = module.im8_network_alb.vpc_id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      location                       = var.gcp_region
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }
  }

  depends_on = [
    module.im8_kms_logging,
    module.im8_network_alb,
  ]
}

resource "google_sql_database" "default" {
  name     = var.db_name
  instance = google_sql_database_instance.im8_postgres.name
  project  = var.gcp_project_id
}

# IAM Service Account Database User for 100% passwordless runtime connections (DB_IAM_AUTH=true)
resource "google_sql_user" "iam_be_user" {
  name     = local.iam_db_user
  instance = google_sql_database_instance.im8_postgres.name
  project  = var.gcp_project_id
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "random_password" "postgres_admin_password" {
  length  = 24
  special = false
}

resource "google_sql_user" "postgres_admin" {
  name     = "postgres"
  instance = google_sql_database_instance.im8_postgres.name
  password = random_password.postgres_admin_password.result
}

# ==============================================================================
# 5. Service Accounts, CMEK Artifact Registry & Least-Privilege IAM
# ==============================================================================
resource "google_service_account" "be_run_sa" {
  project      = var.gcp_project_id
  account_id   = "cs-be-${var.environment}-run"
  display_name = "IM8 Backend Cloud Run Runtime SA"
}

resource "google_service_account" "be_trigger_sa" {
  project      = var.gcp_project_id
  account_id   = "cs-be-${var.environment}-trig"
  display_name = "IM8 Backend Cloud Build Trigger SA"
}

resource "google_service_account" "fe_run_sa" {
  project      = var.gcp_project_id
  account_id   = "cs-fe-${var.environment}-run"
  display_name = "IM8 Frontend Cloud Run Runtime SA"
}

resource "google_service_account" "fe_trigger_sa" {
  project      = var.gcp_project_id
  account_id   = "cs-fe-${var.environment}-trig"
  display_name = "IM8 Frontend Cloud Build Trigger SA"
}

resource "google_artifact_registry_repository" "be_repo" {
  project       = var.gcp_project_id
  location      = var.gcp_region
  repository_id = "cs-be-${var.environment}-repo"
  description   = "CMEK-encrypted Docker repository for ${var.backend_service_name}"
  format        = "DOCKER"
  kms_key_name  = module.im8_kms_logging.artifact_cmek_id

  depends_on = [module.im8_kms_logging]
}

resource "google_artifact_registry_repository" "fe_repo" {
  project       = var.gcp_project_id
  location      = var.gcp_region
  repository_id = "cs-fe-${var.environment}-repo"
  description   = "CMEK-encrypted Docker repository for ${var.frontend_service_name}"
  format        = "DOCKER"
  kms_key_name  = module.im8_kms_logging.artifact_cmek_id

  depends_on = [module.im8_kms_logging]
}

# Backend runtime permissions (scoped to GenMedia bucket to protect immutable audit log bucket)
resource "google_storage_bucket_iam_member" "be_genmedia_admin" {
  bucket = google_storage_bucket.genmedia.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.be_run_sa.email}"
}

resource "google_project_iam_member" "be_runtime_roles" {
  for_each = toset([
    "roles/aiplatform.user",
    "roles/cloudsql.client",
    "roles/cloudsql.instanceUser",
    "roles/workflows.editor",
    "roles/workflows.invoker",
    "roles/iam.serviceAccountTokenCreator",
    "roles/logging.logWriter",
  ])
  project = var.gcp_project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.be_run_sa.email}"
}

resource "google_service_account_iam_member" "be_run_sa_act_as_self" {
  service_account_id = google_service_account.be_run_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.be_run_sa.email}"
}

# Cloud Build Trigger SA permissions
resource "google_project_iam_member" "be_trigger_log_writer" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.be_trigger_sa.email}"
}

resource "google_project_iam_member" "fe_trigger_log_writer" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.fe_trigger_sa.email}"
}

resource "google_artifact_registry_repository_iam_member" "be_ar_writer" {
  project    = var.gcp_project_id
  location   = var.gcp_region
  repository = google_artifact_registry_repository.be_repo.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.be_trigger_sa.email}"
}

resource "google_artifact_registry_repository_iam_member" "fe_ar_writer" {
  project    = var.gcp_project_id
  location   = var.gcp_region
  repository = google_artifact_registry_repository.fe_repo.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.fe_trigger_sa.email}"
}

# ==============================================================================
# 6. Hardened Cloud Run v2 Services (cstudio-be & cstudio-fe)
#    IM8 NS-1: INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER + Direct VPC Egress
# ==============================================================================
resource "google_cloud_run_v2_service" "backend" {
  name                = var.backend_service_name
  location            = var.gcp_region
  project             = var.gcp_project_id
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = false

  template {
    service_account = google_service_account.be_run_sa.email

    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = module.im8_network_alb.vpc_id
        subnetwork = module.im8_network_alb.app_subnet_id
      }
    }

    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello:latest"
      resources {
        limits = {
          cpu    = "2000m"
          memory = "2048Mi"
        }
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "INSTANCE_CONNECTION_NAME"
        value = google_sql_database_instance.im8_postgres.connection_name
      }
      env {
        name  = "DB_NAME"
        value = var.db_name
      }
      env {
        name  = "DB_USER"
        value = local.iam_db_user
      }
      env {
        name  = "DB_IP_TYPE"
        value = "PRIVATE"
      }
      env {
        name  = "DB_IAM_AUTH"
        value = "true"
      }
      env {
        name  = "BACKEND_SERVICE_ACCOUNT_EMAIL"
        value = google_service_account.be_run_sa.email
      }
      env {
        name  = "GENMEDIA_BUCKET"
        value = google_storage_bucket.genmedia.name
      }
      env {
        name  = "SIGNING_SA_EMAIL"
        value = google_service_account.bucket_reader_sa.email
      }
      env {
        name  = "CORS_ORIGINS"
        value = jsonencode([local.alb_origin])
      }
      env {
        name  = "FRONTEND_URL"
        value = local.alb_origin
      }
      env {
        name  = "BACKEND_URL"
        value = local.alb_origin
      }
      env {
        name  = "WORKFLOWS_EXECUTOR_URL"
        value = "${local.alb_origin}/api/workflows-executor"
      }
      env {
        name  = "GOOGLE_TOKEN_AUDIENCE"
        value = var.google_token_audience
      }
      env {
        name  = "IDENTITY_PLATFORM_ALLOWED_ORGS"
        value = var.allowed_orgs
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]
  }
}

# Serverless VPC-native seed job (replaces local cloud-sql-proxy seeding in upstream bootstrap.sh)
resource "google_cloud_run_v2_job" "seed_job" {
  name                = "${var.backend_service_name}-seed"
  location            = var.gcp_region
  project             = var.gcp_project_id
  deletion_protection = false

  template {
    template {
      service_account = google_service_account.be_run_sa.email
      timeout         = "1800s"
      max_retries     = 1

      vpc_access {
        egress = "ALL_TRAFFIC"
        network_interfaces {
          network    = module.im8_network_alb.vpc_id
          subnetwork = module.im8_network_alb.app_subnet_id
        }
      }

      containers {
        image   = "us-docker.pkg.dev/cloudrun/container/hello:latest"
        command = ["python", "-m", "bootstrap.bootstrap"]

        resources {
          limits = {
            cpu    = "2000m"
            memory = "2048Mi"
          }
        }

        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.gcp_project_id
        }
        env {
          name  = "INSTANCE_CONNECTION_NAME"
          value = google_sql_database_instance.im8_postgres.connection_name
        }
        env {
          name  = "DB_NAME"
          value = var.db_name
        }
        env {
          name  = "DB_USER"
          value = local.iam_db_user
        }
        env {
          name  = "DB_IP_TYPE"
          value = "PRIVATE"
        }
        env {
          name  = "DB_IAM_AUTH"
          value = "true"
        }
        env {
          name  = "GENMEDIA_BUCKET"
          value = google_storage_bucket.genmedia.name
        }
        env {
          name  = "ADMIN_USER_EMAIL"
          value = var.admin_user_email
        }
        env {
          name  = "ADMIN_DB_PASS"
          value = google_sql_user.postgres_admin.password
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image, client, client_version]
  }
}

resource "google_cloud_run_v2_service" "frontend" {
  name                = var.frontend_service_name
  location            = var.gcp_region
  project             = var.gcp_project_id
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = false

  template {
    service_account = google_service_account.fe_run_sa.email

    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = module.im8_network_alb.vpc_id
        subnetwork = module.im8_network_alb.app_subnet_id
      }
    }

    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello:latest"
      ports {
        container_port = 8080
      }
      resources {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]
  }
}

# Allow Regional External ALB Serverless NEGs to invoke Frontend & Backend Cloud Run services
# (Protected at network layer by INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER + Regional Cloud Armor WAF)
resource "google_cloud_run_v2_service_iam_member" "fe_alb_invoker" {
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.frontend.location
  name     = google_cloud_run_v2_service.frontend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "be_alb_invoker" {
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.backend.location
  name     = google_cloud_run_v2_service.backend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "be_trigger_run_dev" {
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.backend.location
  name     = google_cloud_run_v2_service.backend.name
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.be_trigger_sa.email}"
}

resource "google_cloud_run_v2_service_iam_member" "fe_trigger_run_dev" {
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.frontend.location
  name     = google_cloud_run_v2_service.frontend.name
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.fe_trigger_sa.email}"
}

resource "google_service_account_iam_member" "be_trigger_sa_user" {
  service_account_id = google_service_account.be_run_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.be_trigger_sa.email}"
}

resource "google_service_account_iam_member" "fe_trigger_sa_user" {
  service_account_id = google_service_account.fe_run_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.fe_trigger_sa.email}"
}

# ==============================================================================
# 7. Optional Cloud Build v2 Repository & Triggers (when github_conn_name != "")
# ==============================================================================
resource "google_cloudbuildv2_repository" "source_repo" {
  count             = var.github_conn_name != "" ? 1 : 0
  provider          = google-beta
  project           = var.gcp_project_id
  name              = var.github_repo_name
  location          = var.gcp_region
  parent_connection = "projects/${var.gcp_project_id}/locations/${var.gcp_region}/connections/${var.github_conn_name}"
  remote_uri        = "https://github.com/${var.github_repo_owner}/${var.github_repo_name}.git"
}

resource "google_cloudbuild_trigger" "be_im8_trigger" {
  count           = var.github_conn_name != "" ? 1 : 0
  project         = var.gcp_project_id
  name            = "${var.backend_service_name}-im8-trigger"
  location        = var.gcp_region
  service_account = google_service_account.be_trigger_sa.id
  filename        = "backend/cloudbuild.im8.yaml"
  included_files  = ["backend/**"]

  substitutions = {
    _REGION       = var.gcp_region
    _REPO_NAME    = google_artifact_registry_repository.be_repo.name
    _SERVICE_NAME = var.backend_service_name
  }

  repository_event_config {
    repository = google_cloudbuildv2_repository.source_repo[0].id
    push {
      branch = "^${var.github_branch_name}$"
    }
  }
}

resource "google_cloudbuild_trigger" "fe_im8_trigger" {
  count           = var.github_conn_name != "" ? 1 : 0
  project         = var.gcp_project_id
  name            = "${var.frontend_service_name}-im8-trigger"
  location        = var.gcp_region
  service_account = google_service_account.fe_trigger_sa.id
  filename        = "frontend/cloudbuild.im8.yaml"
  included_files  = ["frontend/**"]

  substitutions = {
    _REGION       = var.gcp_region
    _REPO_NAME    = google_artifact_registry_repository.fe_repo.name
    _SERVICE_NAME = var.frontend_service_name
  }

  repository_event_config {
    repository = google_cloudbuildv2_repository.source_repo[0].id
    push {
      branch = "^${var.github_branch_name}$"
    }
  }
}

# ==============================================================================
# 8. Optional VPC Service Controls Perimeter (IM8 NS-2, DP-7)
# ==============================================================================
data "google_project" "current" {
  project_id = var.gcp_project_id
}

resource "google_access_context_manager_service_perimeter" "im8_perimeter" {
  count  = var.access_policy_id != "" ? 1 : 0
  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/im8_cstudio_${replace(var.gcp_project_id, "-", "_")}"
  title  = "IM8 Creative Studio VPC-SC Perimeter (${var.gcp_project_id})"

  status {
    resources = ["projects/${data.google_project.current.number}"]
    restricted_services = [
      "aiplatform.googleapis.com",
      "storage.googleapis.com",
      "sqladmin.googleapis.com",
      "secretmanager.googleapis.com",
      "cloudkms.googleapis.com",
      "artifactregistry.googleapis.com",
      "run.googleapis.com",
      "dlp.googleapis.com",
    ]
  }
}

# ==============================================================================
# 9. Cloud Build Builder Roles (Enables gcloud builds submit in fresh projects)
# ==============================================================================
resource "google_project_iam_member" "cloudbuild_builder_roles" {
  for_each = toset([
    "roles/run.admin",
    "roles/iam.serviceAccountUser",
    "roles/secretmanager.secretAccessor",
    "roles/artifactregistry.writer",
  ])
  project = var.gcp_project_id
  role    = each.key
  member  = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}

resource "google_project_iam_member" "compute_builder_roles" {
  for_each = toset([
    "roles/run.admin",
    "roles/iam.serviceAccountUser",
    "roles/secretmanager.secretAccessor",
    "roles/artifactregistry.writer",
    "roles/storage.admin",
    "roles/logging.logWriter",
  ])
  project = var.gcp_project_id
  role    = each.key
  member  = "serviceAccount:${data.google_project.current.number}-compute@developer.gserviceaccount.com"
}

# ==============================================================================
# 10. Organization Policy: Allow All Member Domains (For Cloud Run Ingress)
# ==============================================================================
resource "google_project_organization_policy" "allow_all_member_domains" {
  count      = var.manage_iam_member_domains_org_policy ? 1 : 0
  project    = var.gcp_project_id
  constraint = "iam.allowedPolicyMemberDomains"

  list_policy {
    allow {
      all = true
    }
  }
}
