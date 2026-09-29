# Copyright 2026 Google LLC
# IM8 Sovereign VPC & Regional External ALB Outputs

output "vpc_id" {
  value       = google_compute_network.agency_vpc.id
  description = "Agency VPC network resource ID."
}

output "vpc_name" {
  value       = google_compute_network.agency_vpc.name
  description = "Agency VPC network name."
}

output "app_subnet_id" {
  value       = google_compute_subnetwork.app_subnet.id
  description = "Application subnet resource ID."
}

output "app_subnet_name" {
  value       = google_compute_subnetwork.app_subnet.name
  description = "Application subnet name."
}

output "psa_connection_id" {
  value       = google_service_networking_connection.psa_connection.id
  description = "Private Services Access VPC peering connection ID."
}

output "regional_alb_ip" {
  value       = google_compute_address.regional_alb_ip.address
  description = "Regional External ALB static IPv4 address (Standard Tier in asia-southeast1)."
}

output "regional_waf_policy_id" {
  value       = google_compute_region_security_policy.regional_waf.id
  description = "Regional Cloud Armor WAF security policy ID."
}

output "dns_auth_record_name" {
  value       = length(google_certificate_manager_dns_authorization.custom_domain_auth) > 0 ? google_certificate_manager_dns_authorization.custom_domain_auth[0].dns_resource_record[0].name : ""
  description = "DNS Authorization CNAME record name to add to DNS zone for Google-managed certificate validation."
}

output "dns_auth_record_data" {
  value       = length(google_certificate_manager_dns_authorization.custom_domain_auth) > 0 ? google_certificate_manager_dns_authorization.custom_domain_auth[0].dns_resource_record[0].data : ""
  description = "DNS Authorization CNAME record target/data to add to DNS zone for Google-managed certificate validation."
}
