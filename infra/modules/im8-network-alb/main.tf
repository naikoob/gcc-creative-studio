# Copyright 2026 Google LLC
# IM8 Sovereign VPC Network, Private Services Access, Regional Cloud Armor & Regional External ALB (Pattern A)

# --- 1. Agency VPC Network & Subnets (IM8 NS-1, LM-3) ---

resource "google_compute_network" "agency_vpc" {
  name                    = "cstudio-im8-${var.environment}-vpc"
  project                 = var.gcp_project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# Application Subnet with Private Google Access and 5s VPC Flow Logs (IM8 NS-1, LM-3)
resource "google_compute_subnetwork" "app_subnet" {
  name                     = "cstudio-im8-${var.environment}-app-subnet"
  project                  = var.gcp_project_id
  region                   = var.gcp_region
  network                  = google_compute_network.agency_vpc.id
  ip_cidr_range            = var.app_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Proxy-Only Subnet for Regional Envoy Load Balancer Proxies (IM8 NS-1, DP-3)
resource "google_compute_subnetwork" "proxy_subnet" {
  name          = "cstudio-im8-${var.environment}-proxy-subnet"
  project       = var.gcp_project_id
  region        = var.gcp_region
  network       = google_compute_network.agency_vpc.id
  ip_cidr_range = var.proxy_subnet_cidr
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

# --- 2. Default-Deny Ingress Firewall Rule (IM8 NS-3) ---

resource "google_compute_firewall" "default_deny_ingress" {
  name          = "cstudio-im8-${var.environment}-default-deny-ingress"
  project       = var.gcp_project_id
  network       = google_compute_network.agency_vpc.name
  direction     = "INGRESS"
  priority      = 65534
  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

# --- 3. Private Services Access (PSA) for Private-Only Cloud SQL (IM8 NS-4) ---

resource "google_compute_global_address" "psa_ip_range" {
  name          = "cstudio-im8-${var.environment}-psa-range"
  project       = var.gcp_project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.agency_vpc.id
}

resource "google_service_networking_connection" "psa_connection" {
  network                 = google_compute_network.agency_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa_ip_range.name]
}

# --- 4. Cloud Router & Cloud NAT for Controlled Container Egress (IM8 NS-2) ---

resource "google_compute_router" "nat_router" {
  name    = "cstudio-im8-${var.environment}-router"
  project = var.gcp_project_id
  region  = var.gcp_region
  network = google_compute_network.agency_vpc.id
}

resource "google_compute_router_nat" "app_nat" {
  name                               = "cstudio-im8-${var.environment}-nat"
  project                            = var.gcp_project_id
  router                             = google_compute_router.nat_router.name
  region                             = var.gcp_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.app_subnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# --- 5. Regional External Static IP (Standard Tier in Singapore — IM8 DP-1, DP-3, NS-1) ---

resource "google_compute_address" "regional_alb_ip" {
  name         = "cstudio-im8-${var.environment}-alb-ip"
  project      = var.gcp_project_id
  region       = var.gcp_region
  network_tier = "STANDARD"
}

# --- 6. Regional Cloud Armor WAF Policy (OWASP CRS 3.3 — IM8 AS-1, NS-5) ---

resource "google_compute_region_security_policy" "regional_waf" {
  provider    = google-beta
  name        = "cstudio-im8-${var.environment}-waf"
  project     = var.gcp_project_id
  region      = var.gcp_region
  description = "IM8-compliant Regional Cloud Armor policy enforcing OWASP CRS 3.3 and rate limiting"
  type        = "CLOUD_ARMOR"

  # Rule 900: Optional Singapore Geo-Fencing
  dynamic "rules" {
    for_each = var.enforce_sg_geofence ? [1] : []
    content {
      action      = "deny(403)"
      priority    = 900
      description = "Block non-Singapore traffic (IM8 Sovereign Geo-Fence)"
      match {
        expr {
          expression = "origin.region_code != 'SG'"
        }
      }
    }
  }

  # Rule 1000: Block SQL Injection (OWASP CRS 3.3)
  rules {
    action      = "deny(403)"
    priority    = 1000
    description = "OWASP CRS 3.3 SQL Injection protection (IM8 AS-1)"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable')"
      }
    }
  }

  # Rule 1001: Block Cross-Site Scripting (OWASP CRS 3.3)
  rules {
    action      = "deny(403)"
    priority    = 1001
    description = "OWASP CRS 3.3 XSS protection (IM8 AS-1)"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable')"
      }
    }
  }

  # Rule 1002: Block Remote Code Execution (OWASP CRS 3.3)
  rules {
    action      = "deny(403)"
    priority    = 1002
    description = "OWASP CRS 3.3 RCE protection (IM8 AS-1)"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rce-v33-stable')"
      }
    }
  }

  # Rule 1003: Block Local File Inclusion (OWASP CRS 3.3)
  rules {
    action      = "deny(403)"
    priority    = 1003
    description = "OWASP CRS 3.3 LFI protection (IM8 AS-1)"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('lfi-v33-stable')"
      }
    }
  }

  # Rule 2000: Per-IP Rate Limiting (IM8 AS-14, NS-5)
  rules {
    action      = "throttle"
    priority    = 2000
    description = "Per-IP rate limiting threshold"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.rate_limit_rpm
        interval_sec = 60
      }
    }
  }

  # Default Allow Rule
  rules {
    action      = "allow"
    priority    = 2147483647
    description = "Default allow rule"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

# --- 7. Regional Serverless NEGs & Backend Services (Pattern A Unified Frontend + Backend) ---

resource "google_compute_region_network_endpoint_group" "frontend_neg" {
  name                  = "cstudio-im8-${var.environment}-fe-neg"
  project               = var.gcp_project_id
  region                = var.gcp_region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = var.frontend_service_name
  }
}

resource "google_compute_region_network_endpoint_group" "backend_neg" {
  name                  = "cstudio-im8-${var.environment}-be-neg"
  project               = var.gcp_project_id
  region                = var.gcp_region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = var.backend_service_name
  }
}

resource "google_compute_region_backend_service" "frontend_backend" {
  provider              = google-beta
  name                  = "cstudio-im8-${var.environment}-fe-bs"
  project               = var.gcp_project_id
  region                = var.gcp_region
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  security_policy       = google_compute_region_security_policy.regional_waf.id

  backend {
    group           = google_compute_region_network_endpoint_group.frontend_neg.id
    capacity_scaler = 1.0
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_region_backend_service" "api_backend" {
  provider              = google-beta
  name                  = "cstudio-im8-${var.environment}-be-bs"
  project               = var.gcp_project_id
  region                = var.gcp_region
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  security_policy       = google_compute_region_security_policy.regional_waf.id

  backend {
    group           = google_compute_region_network_endpoint_group.backend_neg.id
    capacity_scaler = 1.0
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

# --- 8. Regional URL Map, TLS 1.2+ Restricted SSL Policy & Target HTTPS Proxy (IM8 DP-3) ---

resource "google_compute_region_url_map" "unified_url_map" {
  name            = "cstudio-im8-${var.environment}-url-map"
  project         = var.gcp_project_id
  region          = var.gcp_region
  default_service = google_compute_region_backend_service.frontend_backend.id

  host_rule {
    hosts        = ["*"]
    path_matcher = "unified-paths"
  }

  path_matcher {
    name            = "unified-paths"
    default_service = google_compute_region_backend_service.frontend_backend.id

    path_rule {
      paths   = ["/api", "/api/*"]
      service = google_compute_region_backend_service.api_backend.id
    }
  }
}

resource "google_compute_region_ssl_policy" "restricted_tls" {
  name            = "cstudio-im8-${var.environment}-tls-policy"
  project         = var.gcp_project_id
  region          = var.gcp_region
  profile         = "RESTRICTED"
  min_tls_version = "TLS_1_2"
}

# --- 7b. Regional SSL Certificates & Certificate Manager (IM8 DP-3, NS-1) ---

resource "google_compute_region_ssl_certificate" "alb_cert" {
  count       = var.custom_domain == "" ? 1 : 0
  name_prefix = "cstudio-im8-${var.environment}-cert-"
  project     = var.gcp_project_id
  region      = var.gcp_region
  private_key = var.ssl_private_key_pem
  certificate = var.ssl_certificate_pem

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_certificate_manager_dns_authorization" "custom_domain_auth" {
  count       = var.custom_domain != "" ? 1 : 0
  name        = "cstudio-im8-${var.environment}-dns-auth"
  location    = var.gcp_region
  project     = var.gcp_project_id
  domain      = var.custom_domain
  description = "Regional DNS authorization for ${var.custom_domain}"
}

resource "google_certificate_manager_certificate" "custom_domain_cert" {
  count       = var.custom_domain != "" ? 1 : 0
  name        = "cstudio-im8-${var.environment}-managed-cert"
  location    = var.gcp_region
  project     = var.gcp_project_id
  description = "Regional Google-managed certificate for ${var.custom_domain}"

  managed {
    domains = [var.custom_domain]
    dns_authorizations = [
      google_certificate_manager_dns_authorization.custom_domain_auth[0].id
    ]
  }
}

resource "google_compute_region_target_https_proxy" "https_proxy" {
  name                             = "cstudio-im8-${var.environment}-https-proxy"
  project                          = var.gcp_project_id
  region                           = var.gcp_region
  url_map                          = google_compute_region_url_map.unified_url_map.id
  ssl_certificates                 = var.custom_domain == "" ? [google_compute_region_ssl_certificate.alb_cert[0].id] : null
  certificate_manager_certificates = var.custom_domain != "" ? [google_certificate_manager_certificate.custom_domain_cert[0].id] : null
  ssl_policy                       = google_compute_region_ssl_policy.restricted_tls.id
}

resource "google_compute_forwarding_rule" "https_forwarding_rule" {
  name                  = "cstudio-im8-${var.environment}-https-fwd"
  project               = var.gcp_project_id
  region                = var.gcp_region
  network_tier          = "STANDARD"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_address.regional_alb_ip.id
  port_range            = "443"
  target                = google_compute_region_target_https_proxy.https_proxy.id
  network               = google_compute_network.agency_vpc.id

  depends_on = [google_compute_subnetwork.proxy_subnet]
}
