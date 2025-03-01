// Author: CyberCraft Alchemist
// Core library for the network vulnerability scanner

use std::net::IpAddr;

// Module declarations
pub mod constants;
pub mod models;
pub mod scanner;
pub mod utils;
pub mod report;
pub mod resolver;
pub mod cveapi;

// Re-exports for convenience
pub use models::{ScanConfig, ScanResult, Vulnerability, PortResult, HostInfo};
pub use constants::{VERSION, TOOL_NAME};
pub use scanner::{scan_port_range, quick_scan, ot_scan, check_vulnerability, discover_hosts};
pub use scanner as scanner_module;

// Function to get version
pub fn version() -> &'static str {
    constants::VERSION
}

// Wrapper function for scanning
pub fn scan(config: ScanConfig) -> Vec<ScanResult> {
    scanner::scan(config)
}

// Banner information
pub fn banner() -> String {
    format!("{} v{}", constants::TOOL_NAME, constants::VERSION)
}

/// Initialize the vulnerability scanner
pub fn init() {
    // Initialize CVE cache
    cveapi::init_cve_cache();
}

// Utility functions that use components from different modules

/// Check if a specific port is open
pub fn check_port(host: &str, port: u16, timeout_ms: u64) -> bool {
    // Parse host to IpAddr
    if let Ok(ip) = host.parse::<IpAddr>() {
        utils::is_port_open(&ip, port, timeout_ms)
    } else {
        // Try to resolve hostname
        if let Ok(ips) = resolver::resolve_hostname(host) {
            for ip in ips {
                if utils::is_port_open(&ip, port, timeout_ms) {
                    return true;
                }
            }
            false
        } else {
            false
        }
    }
}

/// Check if a host is online
pub fn is_host_online(host: &str, timeout_ms: u64) -> bool {
    // Parse host to IpAddr
    if let Ok(ip) = host.parse::<IpAddr>() {
        utils::ping_host(&ip) || utils::tcp_ping_host(&ip, timeout_ms)
    } else {
        // Try to resolve hostname
        if let Ok(ips) = resolver::resolve_hostname(host) {
            for ip in ips {
                if utils::ping_host(&ip) || utils::tcp_ping_host(&ip, timeout_ms) {
                    return true;
                }
            }
            false
        } else {
            false
        }
    }
}

/// Resolve a hostname to IP addresses
pub fn resolve_host(hostname: &str) -> Vec<String> {
    match resolver::resolve_hostname(hostname) {
        Ok(ips) => ips.iter().map(|ip| ip.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Perform reverse DNS lookup
pub fn reverse_lookup(ip: &str) -> Option<String> {
    if let Ok(ip_addr) = ip.parse::<IpAddr>() {
        resolver::reverse_lookup(&ip_addr)
    } else {
        None
    }
}

/// Get banner from an open port
pub fn get_banner(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    // Parse host to IpAddr
    if let Ok(ip) = host.parse::<IpAddr>() {
        utils::get_service_banner(&ip, port, timeout_ms)
    } else {
        // Try to resolve hostname
        if let Ok(ips) = resolver::resolve_hostname(host) {
            for ip in ips {
                if let Some(banner) = utils::get_service_banner(&ip, port, timeout_ms) {
                    return Some(banner);
                }
            }
            None
        } else {
            None
        }
    }
}

/// Identify service on a port
pub fn identify_service(port: u16, banner: &str) -> String {
    utils::identify_service(port, banner)
}

/// Check vulnerabilities for a service
pub fn check_vulnerabilities(service: &str, banner: &str, offline_mode: bool) -> Vec<Vulnerability> {
    cveapi::check_service_vulnerabilities(service, banner, !offline_mode)
}

/// Generate a report from scan results
pub fn generate_report(results: &[ScanResult], format: &str, filename: &str) -> std::io::Result<()> {
    match format.to_uppercase().as_str() {
        "TEXT" => report::generate_text_report(results, filename),
        "HTML" => report::generate_html_report(results, filename),
        "JSON" => report::generate_json_report(results, filename),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unsupported report format: {}", format),
        )),
    }
}
