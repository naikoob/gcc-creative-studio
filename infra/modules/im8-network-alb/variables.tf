# Copyright 2026 Google LLC
# IM8 Sovereign Network, VPC Segmentation & Regional External ALB (Pattern A) Variables

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

variable "backend_service_name" {
  type        = string
  description = "Name of the backend Cloud Run service (e.g., cstudio-be)."
}

variable "frontend_service_name" {
  type        = string
  description = "Name of the frontend Cloud Run service (e.g., cstudio-fe)."
}

variable "app_subnet_cidr" {
  type        = string
  description = "CIDR block for the private application subnet."
  default     = "10.0.1.0/24"
}

variable "proxy_subnet_cidr" {
  type        = string
  description = "CIDR block for the Regional Managed Proxy subnet (Envoy proxies)."
  default     = "10.0.100.0/24"
}

variable "ssl_certificate_pem" {
  type        = string
  description = "PEM-encoded TLS certificate for the Regional HTTPS Load Balancer."
  sensitive   = true
}

variable "ssl_private_key_pem" {
  type        = string
  description = "PEM-encoded private key for the Regional HTTPS Load Balancer."
  sensitive   = true
}

variable "enforce_sg_geofence" {
  type        = bool
  description = "Restrict inbound ALB traffic strictly to Singapore IP origins (origin.region_code == 'SG')."
  default     = false
}

variable "rate_limit_rpm" {
  type        = number
  description = "Per-IP rate limit threshold (requests per minute) enforced by Regional Cloud Armor."
  default     = 600
}

variable "custom_domain" {
  type        = string
  description = "Optional custom FQDN for the application (e.g. creative-studio.bookian.demo.altostrat.com). When set, provisions a regional Google-managed certificate via Certificate Manager."
  default     = ""
}
