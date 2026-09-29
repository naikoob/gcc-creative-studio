#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# IM8-Compliant Bootstrap Script for Creative Studio (Pattern A)
# Deploys Sovereign VPC, Regional Cloud Armor WAF, Regional External ALB,
# CMEK HSM keys, 365-day Audit Logs, Regional HA Private Cloud SQL, and
# Cloud Run Frontend (Nginx unprivileged) + Backend (FastAPI non-root) in asia-southeast1.
# Leaves upstream bootstrap.sh untouched for zero-conflict upstream merges.

set -euo pipefail

# Avoid ECP proxy socket hangs on internal Google workstations
export CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE=false
export CLOUDSDK_CONTEXT_AWARE_USE_ECP_HTTP_PROXY=false

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="${REPO_ROOT}/infra/environments/im8-prod"
TFVARS_FILE="${ENV_DIR}/im8.tfvars"
CERT_DIR="${ENV_DIR}/.certs"
REGION="asia-southeast1"
BE_SERVICE_NAME="cstudio-be"
FE_SERVICE_NAME="cstudio-fe"

# Default configuration parameters (can be overridden via env vars or flags)
GCP_PROJECT_ID="${GCP_PROJECT_ID:-}"
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}"
OAUTH_CLIENT_ID="${OAUTH_CLIENT_ID:-}"
ALLOWED_ORGS="${ALLOWED_ORGS:-tech.gov.sg}"
ADMIN_USER_EMAIL="${ADMIN_USER_EMAIL:-}"
ENFORCE_SG_GEOFENCE="${ENFORCE_SG_GEOFENCE:-false}"
AUTO_APPROVE="${AUTO_APPROVE:-false}"

C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[1;34m'
C_CYAN='\033[1;36m'

info()    { echo -e "${C_CYAN}➡️  $1${C_RESET}"; }
prompt()  { echo -e "${C_BLUE}🤔  $1${C_RESET}"; }
warn()    { echo -e "${C_YELLOW}⚠️  $1${C_RESET}"; }
fail()    { echo -e "${C_RED}❌  $1${C_RESET}" >&2; exit 1; }
success() { echo -e "${C_GREEN}✅  $1${C_RESET}"; }
step()    { echo -e "\n${C_BLUE}=== Step $1: $2 ===${C_RESET}"; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p|--project)
        GCP_PROJECT_ID="$2"; shift 2 ;;
      -c|--oauth-client-id)
        OAUTH_CLIENT_ID="$2"; shift 2 ;;
      -d|--domain)
        CUSTOM_DOMAIN="$2"; shift 2 ;;
      -a|--admin-email)
        ADMIN_USER_EMAIL="$2"; shift 2 ;;
      -o|--orgs)
        ALLOWED_ORGS="$2"; shift 2 ;;
      -g|--geofence)
        ENFORCE_SG_GEOFENCE="true"; shift ;;
      -y|--yes|--auto-approve)
        AUTO_APPROVE="true"; shift ;;
      *)
        shift ;;
    esac
  done
}

check_prereqs() {
  step 1 "Checking Prerequisites"
  for cmd in gcloud terraform openssl jq; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Required command '$cmd' not found in PATH."
  done
  success "Prerequisites verified (gcloud, terraform, openssl, jq)."
}

configure_inputs() {
  step 2 "Configuring IM8 Deployment Parameters"
  local default_proj
  default_proj="$(gcloud config get-value project 2>/dev/null || true)"

  if [[ -z "$GCP_PROJECT_ID" ]]; then
    if [[ -t 0 && -e /dev/tty ]]; then
      read -r -p "   GCP Project ID [${default_proj}]: " input_proj </dev/tty
      GCP_PROJECT_ID="${input_proj:-$default_proj}"
    else
      GCP_PROJECT_ID="$default_proj"
    fi
  fi
  [[ -n "$GCP_PROJECT_ID" ]] || fail "GCP Project ID is required."
  gcloud config set project "$GCP_PROJECT_ID" >/dev/null

  if [[ -z "$OAUTH_CLIENT_ID" ]]; then
    if [[ -t 0 && -e /dev/tty ]]; then
      read -r -p "   Custom Agency FQDN for Regional ALB (optional, e.g. cstudio.agency.gov.sg) []: " CUSTOM_DOMAIN </dev/tty
      read -r -p "   OAuth 2.0 Web Client ID (GOOGLE_CLIENT_ID / GOOGLE_TOKEN_AUDIENCE): " OAUTH_CLIENT_ID </dev/tty
    else
      local proj_num
      proj_num="$(gcloud projects describe "$GCP_PROJECT_ID" --format="value(projectNumber)" 2>/dev/null || echo "1038219280071")"
      OAUTH_CLIENT_ID="${proj_num}-im8.apps.googleusercontent.com"
      info "Non-interactive run: generated fallback OAuth Client ID: ${OAUTH_CLIENT_ID}"
    fi
  fi

  if [[ -z "$ADMIN_USER_EMAIL" ]]; then
    local default_admin
    default_admin="$(gcloud config get-value account 2>/dev/null || echo "system")"
    if [[ -t 0 && -e /dev/tty ]]; then
      read -r -p "   Initial Admin User Email [${default_admin}]: " input_admin </dev/tty
      ADMIN_USER_EMAIL="${input_admin:-$default_admin}"
    else
      ADMIN_USER_EMAIL="$default_admin"
    fi
  fi

  success "Configured project '${GCP_PROJECT_ID}' in sovereign region '${REGION}' (Admin: ${ADMIN_USER_EMAIL})."
}

enable_bootstrap_apis() {
  step 3 "Enabling Core Bootstrap APIs"
  gcloud services enable \
    serviceusage.googleapis.com \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    secretmanager.googleapis.com \
    sqladmin.googleapis.com \
    cloudkms.googleapis.com \
    compute.googleapis.com \
    servicenetworking.googleapis.com \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    cloudbuild.googleapis.com \
    aiplatform.googleapis.com \
    workflows.googleapis.com \
    dlp.googleapis.com \
    --project="$GCP_PROJECT_ID"
  success "Core APIs enabled."
}

ensure_secret() {
  local secret_name="$1"
  local secret_val="$2"
  if ! gcloud secrets describe "$secret_name" --project="$GCP_PROJECT_ID" >/dev/null 2>&1; then
    info "Creating secret '${secret_name}' in ${REGION}..."
    gcloud secrets create "$secret_name" \
      --replication-policy="user-managed" \
      --locations="$REGION" \
      --project="$GCP_PROJECT_ID" \
      --quiet
  fi
  printf "%s" "$secret_val" | gcloud secrets versions add "$secret_name" \
    --data-file=- \
    --project="$GCP_PROJECT_ID" \
    --quiet
}

configure_secrets_and_certs() {
  step 4 "Configuring Regional Secret Manager & ALB TLS Certificates"

  ensure_secret "GOOGLE_CLIENT_ID" "$OAUTH_CLIENT_ID"
  ensure_secret "GOOGLE_TOKEN_AUDIENCE" "$OAUTH_CLIENT_ID"
  success "Populated 'GOOGLE_CLIENT_ID' and 'GOOGLE_TOKEN_AUDIENCE' in Secret Manager (DB is 100% IAM passwordless)."

  mkdir -p "$CERT_DIR"
  local cert_file="${CERT_DIR}/alb.crt"
  local key_file="${CERT_DIR}/alb.key"
  local cn="${CUSTOM_DOMAIN:-cstudio.im8.internal}"

  if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
    info "Generating TLS certificate for Regional External ALB (CN=${cn})..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$key_file" \
      -out "$cert_file" \
      -subj "/C=SG/ST=Singapore/L=Singapore/O=Singapore Government/CN=${cn}" >/dev/null 2>&1
    chmod 600 "$key_file"
    success "Generated Regional ALB TLS certificate at ${cert_file} (replace with agency CA cert for production FQDN)."
  else
    info "Reusing existing TLS certificate in ${CERT_DIR}."
  fi
}

deploy_terraform() {
  step 5 "Provisioning IM8 Infrastructure via Terraform"
  local tfstate_bucket="${GCP_PROJECT_ID}-cstudio-im8-tfstate"

  if ! gcloud storage buckets describe "gs://${tfstate_bucket}" --project="$GCP_PROJECT_ID" >/dev/null 2>&1; then
    info "Creating sovereign Terraform state bucket gs://${tfstate_bucket} in ${REGION}..."
    gcloud storage buckets create "gs://${tfstate_bucket}" \
      --project="$GCP_PROJECT_ID" \
      --location="$REGION" \
      --uniform-bucket-level-access \
      --public-access-prevention
  fi

  cat > "${ENV_DIR}/backend.tf" <<EOF
terraform {
  backend "gcs" {
    bucket = "${tfstate_bucket}"
    prefix = "infra/im8-prod/state"
  }
}
EOF

  cat > "$TFVARS_FILE" <<EOF
gcp_project_id        = "${GCP_PROJECT_ID}"
gcp_region            = "${REGION}"
environment           = "production"
custom_domain         = "${CUSTOM_DOMAIN}"
backend_service_name  = "${BE_SERVICE_NAME}"
frontend_service_name = "${FE_SERVICE_NAME}"
google_token_audience = "${OAUTH_CLIENT_ID}"
allowed_orgs          = "${ALLOWED_ORGS}"
admin_user_email      = "${ADMIN_USER_EMAIL}"
enforce_sg_geofence   = ${ENFORCE_SG_GEOFENCE}
EOF

  pushd "$ENV_DIR" >/dev/null
  terraform init -reconfigure
  terraform plan -var-file="$TFVARS_FILE"
  local proceed="false"
  if [[ "$AUTO_APPROVE" == "true" ]]; then
    proceed="true"
  else
    prompt "Proceed with 'terraform apply' for IM8 infrastructure? (y/n)"
    read -r reply </dev/tty
    if [[ "$reply" =~ ^[Yy]$ ]]; then
      proceed="true"
    fi
  fi

  if [[ "$proceed" == "true" ]]; then
    terraform apply -auto-approve -var-file="$TFVARS_FILE"
    ALB_ORIGIN="$(terraform output -raw regional_alb_origin)"
    BE_REPO_NAME="$(terraform output -raw backend_repo_name)"
    FE_REPO_NAME="$(terraform output -raw frontend_repo_name)"
    success "Terraform apply completed. Regional ALB Origin: ${ALB_ORIGIN}"
  else
    warn "Terraform apply skipped."
    popd >/dev/null
    exit 0
  fi
  popd >/dev/null
}

build_and_deploy_containers() {
  step 6 "Building, Seeding & Deploying Hardened Containers (Cloud Run FE + BE)"
  local proceed_build="false"
  if [[ "$AUTO_APPROVE" == "true" ]]; then
    proceed_build="true"
  else
    prompt "Submit Cloud Build jobs for cstudio-be (Dockerfile.im8), execute VPC database seeding, and deploy cstudio-fe (Dockerfile.im8 + nginx.im8.conf) now? (y/n)"
    read -r reply </dev/tty
    if [[ "$reply" =~ ^[Yy]$ ]]; then
      proceed_build="true"
    fi
  fi

  if [[ "$proceed_build" != "true" ]]; then
    info "Skipping container build. You can run gcloud builds submit using backend/cloudbuild.im8.yaml and frontend/cloudbuild.im8.yaml anytime."
    return
  fi

  info "Building and deploying Backend (${BE_SERVICE_NAME})..."
  gcloud builds submit "$REPO_ROOT" \
    --config="${REPO_ROOT}/backend/cloudbuild.im8.yaml" \
    --region="$REGION" \
    --substitutions="_REGION=${REGION},_REPO_NAME=${BE_REPO_NAME},_SERVICE_NAME=${BE_SERVICE_NAME}" \
    --project="$GCP_PROJECT_ID"

  info "Executing VPC-native passwordless Database Migrations & Asset Seeding (${BE_SERVICE_NAME}-seed)..."
  gcloud run jobs update "${BE_SERVICE_NAME}-seed" \
    --image="${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${BE_REPO_NAME}/${BE_SERVICE_NAME}:latest" \
    --region="$REGION" \
    --project="$GCP_PROJECT_ID" \
    --quiet
  gcloud run jobs execute "${BE_SERVICE_NAME}-seed" \
    --region="$REGION" \
    --project="$GCP_PROJECT_ID" \
    --wait

  info "Building and deploying Frontend (${FE_SERVICE_NAME})..."
  gcloud builds submit "$REPO_ROOT" \
    --config="${REPO_ROOT}/frontend/cloudbuild.im8.yaml" \
    --region="$REGION" \
    --substitutions="_REGION=${REGION},_REPO_NAME=${FE_REPO_NAME},_SERVICE_NAME=${FE_SERVICE_NAME}" \
    --project="$GCP_PROJECT_ID"

  success "Both cstudio-be and cstudio-fe are deployed and seeded behind the Regional External ALB!"
  echo -e "\n${C_GREEN}========================================================================${C_RESET}"
  echo -e "${C_GREEN} 🛡️  IM8 Creative Studio Deployment Complete!${C_RESET}"
  echo -e " 🔗  Regional ALB Origin: ${C_YELLOW}${ALB_ORIGIN}${C_RESET}"
  echo -e " 🔐  Action Required: Add ${C_YELLOW}${ALB_ORIGIN}${C_RESET} to Authorized JavaScript Origins"
  echo -e "     in your OAuth 2.0 Web Client: https://console.cloud.google.com/apis/credentials?project=${GCP_PROJECT_ID}"
  echo -e "${C_GREEN}========================================================================${C_RESET}"
}

main() {
  parse_args "$@"
  check_prereqs
  configure_inputs
  enable_bootstrap_apis
  configure_secrets_and_certs
  deploy_terraform
  build_and_deploy_containers
}

main "$@"
