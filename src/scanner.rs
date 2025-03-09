// Author: CyberCraft Alchemist
// Core network scanning and vulnerability detection engine

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use rayon::prelude::*;
use chrono::Local;

use crate::models::{ScanConfig, ScanResult, PortResult, Vulnerability, HostInfo};
use crate::utils;
use crate::resolver;
use crate::cveapi;
use crate::constants;
use crate::plugins::PluginRegistry;

/// Main scanner function that orchestrates the entire scanning process
pub fn scan(config: ScanConfig) -> Vec<ScanResult> {
    let _start_time = Instant::now();
    
    // Resolve targets to IP addresses
    let mut targets = resolve_targets(&config);
    
    // Randomize targets if requested
    if config.randomize_scan {
        utils::randomize_hosts(&mut targets);
    }
    
    // Create a thread-safe container for results
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // Scan each target in parallel
    targets.par_iter().for_each(|ip| {
        let host_result = scan_host(ip, &config);
        
        // If we found any open ports, add the result
        if !host_result.open_ports.is_empty() {
            let mut results_guard = results.lock().unwrap();
            results_guard.push(host_result);
        }
    });
    
    // Return the results
    let final_results = Arc::try_unwrap(results)
        .unwrap()
        .into_inner()
        .unwrap();
    
    final_results
}

/// Scan a single host for open ports and vulnerabilities
fn scan_host(ip: &IpAddr, config: &ScanConfig) -> ScanResult {
    let _start_time = Instant::now();
    
    // Resolve hostname
    let hostname = resolver::resolve_hostname_comprehensive(ip);
    
    // Ping host to check if it's online
    let is_online = utils::ping_host(ip) || utils::tcp_ping_host(ip, config.timeout_ms);
    
    // If host is not online and we're not doing a complete scan, return early
    if !is_online && !config.scan_offline_hosts {
        return ScanResult {
            host: ip.to_string(),
            hostname,
            is_online,
            scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            open_ports: Vec::new(),
            os_info: None,
            vulnerabilities_summary: None,
            attack_paths: None,
        };
    }
    
    // Determine which ports to scan
    let ports_to_scan: Vec<u16> = if config.ports.is_empty() {
        // If no ports are specified, scan common ports
        constants::COMMON_PORTS.keys().cloned().collect()
    } else {
        config.ports.clone()
    };
    
    // Randomize ports if requested
    let mut ports = ports_to_scan.clone();
    if config.randomize_scan {
        utils::randomize_ports(&mut ports);
    }
    
    // Container for open port results
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    
    // Scan ports in parallel
    ports.par_iter().for_each(|port| {
        if utils::is_port_open(ip, *port, config.timeout_ms) {
            // Get service banner
            let banner = utils::get_service_banner(ip, *port, config.timeout_ms)
                .unwrap_or_else(|| String::from("No banner"));
            
            // Identify service
            let service = utils::identify_service(*port, &banner);
            
            // Check for vulnerabilities using plugin system
            let mut vulnerabilities = Vec::new();
            
            // Create plugin registry
            let plugin_registry = PluginRegistry::new();
            
            // If enhanced vulnerability detection is enabled, use all plugins
            if config.enhanced_vuln_detection {
                vulnerabilities = plugin_registry.detect_vulnerabilities(
                    &service,
                    &banner,
                    config
                );
            } else {
                // Otherwise use the legacy approach for backward compatibility
                vulnerabilities = cveapi::check_service_vulnerabilities(
                    &service, 
                    &banner, 
                    !config.offline_mode
                );
            }
            
            // Create port result
            let port_result = PortResult {
                port: *port,
                service,
                banner,
                vulnerabilities,
            };
            
            // Add to results
            let mut open_ports_guard = open_ports.lock().unwrap();
            open_ports_guard.push(port_result);
        }
    });
    
    // Collect open ports
    let mut open_port_results = Arc::try_unwrap(open_ports)
        .unwrap()
        .into_inner()
        .unwrap();
    
    // Sort ports for better readability
    open_port_results.sort_by_key(|p| p.port);
    
    // Gather OS information if possible
    let os_info = if !open_port_results.is_empty() {
        let banners: Vec<String> = open_port_results.iter()
            .map(|p| p.banner.clone())
            .collect();
        
        utils::fingerprint_os(&banners)
    } else {
        None
    };
    
    // Create vulnerability summary if enhanced detection is enabled
    let vulnerabilities_summary = if config.enhanced_vuln_detection {
        Some(generate_vulnerability_summary(&open_port_results))
    } else {
        None
    };
    
    // Generate attack paths if analysis is enabled
    let attack_paths = if config.attack_path_analysis {
        // Collect all vulnerabilities from all ports
        let all_vulnerabilities: Vec<Vulnerability> = open_port_results.iter()
            .flat_map(|port| port.vulnerabilities.clone())
            .collect();
            
        if !all_vulnerabilities.is_empty() {
            // Use the attack path generator
            Some(cveapi::generate_attack_paths(&all_vulnerabilities))
        } else {
            None
        }
    } else {
        None
    };
    
    // Create final result
    ScanResult {
        host: ip.to_string(),
        hostname,
        is_online,
        scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        open_ports: open_port_results,
        os_info,
        vulnerabilities_summary,
        attack_paths,
    }
}

/// Resolve a target specification to a list of IPs
fn resolve_targets(config: &ScanConfig) -> Vec<IpAddr> {
    resolver::resolve_targets(&config.target)
}

/// Scan a specific port range on a target
pub fn scan_port_range(target: &str, start_port: u16, end_port: u16, config: &ScanConfig) -> Vec<u16> {
    // Parse target as IP
    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Try to resolve hostname
            if let Ok(ips) = resolver::resolve_hostname(target) {
                if ips.is_empty() {
                    return Vec::new();
                }
                ips[0] // Use the first resolved IP
            } else {
                return Vec::new();
            }
        }
    };
    
    // Create port range
    let mut ports: Vec<u16> = (start_port..=end_port).collect();
    
    // Randomize if requested
    if config.randomize_scan {
        utils::randomize_ports(&mut ports);
    }
    
    // Scan ports in parallel
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    
    ports.par_iter().for_each(|port| {
        if utils::is_port_open(&ip, *port, config.timeout_ms) {
            let mut open_ports_guard = open_ports.lock().unwrap();
            open_ports_guard.push(*port);
        }
    });
    
    // Return open ports
    let mut result = Arc::try_unwrap(open_ports)
        .unwrap()
        .into_inner()
        .unwrap();
    
    // Sort for readability
    result.sort();
    
    result
}

/// Quick scan of a host for common vulnerabilities
pub fn quick_scan(target: &str, config: &ScanConfig) -> ScanResult {
    // Parse target as IP
    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Try to resolve hostname
            if let Ok(ips) = resolver::resolve_hostname(target) {
                if ips.is_empty() {
                    return ScanResult {
                        host: target.to_string(),
                        hostname: target.to_string(),
                        is_online: false,
                        scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        open_ports: Vec::new(),
                        os_info: None,
                        vulnerabilities_summary: None,
                        attack_paths: None,
                    };
                }
                ips[0] // Use the first resolved IP
            } else {
                return ScanResult {
                    host: target.to_string(),
                    hostname: target.to_string(),
                    is_online: false,
                    scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    open_ports: Vec::new(),
                    os_info: None,
                    vulnerabilities_summary: None,
                    attack_paths: None,
                };
            }
        }
    };
    
    // Scan only common ports
    let mut config = config.clone();
    config.ports = constants::COMMON_PORTS.keys().cloned().collect();
    
    scan_host(&ip, &config)
}

/// OT-specific scan focusing on industrial protocols
pub fn ot_scan(target: &str, config: &ScanConfig) -> ScanResult {
    // Parse target as IP
    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Try to resolve hostname
            if let Ok(ips) = resolver::resolve_hostname(target) {
                if ips.is_empty() {
                    return ScanResult {
                        host: target.to_string(),
                        hostname: target.to_string(),
                        is_online: false,
                        scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        open_ports: Vec::new(),
                        os_info: None,
                        vulnerabilities_summary: None,
                        attack_paths: None,
                    };
                }
                ips[0] // Use the first resolved IP
            } else {
                return ScanResult {
                    host: target.to_string(),
                    hostname: target.to_string(),
                    is_online: false,
                    scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    open_ports: Vec::new(),
                    os_info: None,
                    vulnerabilities_summary: None,
                    attack_paths: None,
                };
            }
        }
    };
    
    // Get OT-specific ports from constants
    let ot_ports: Vec<u16> = constants::OT_PROTOCOLS
        .keys()
        .cloned()
        .collect();
    
    // Create a new config with OT ports
    let mut ot_config = config.clone();
    ot_config.ports = ot_ports;
    
    scan_host(&ip, &ot_config)
}

/// Check a specific vulnerability on a host
pub fn check_vulnerability(target: &str, port: u16, vuln_id: &str, config: &ScanConfig) -> Option<Vulnerability> {
    // Parse target as IP
    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Try to resolve hostname
            if let Ok(ips) = resolver::resolve_hostname(target) {
                if ips.is_empty() {
                    return None;
                }
                ips[0] // Use the first resolved IP
            } else {
                return None;
            }
        }
    };
    
    // Check if port is open
    if !utils::is_port_open(&ip, port, config.timeout_ms) {
        return None;
    }
    
    // Get banner
    let banner = match utils::get_service_banner(&ip, port, config.timeout_ms) {
        Some(banner) => banner,
        None => return None,
    };
    
    // Identify service
    let service = utils::identify_service(port, &banner);
    
    // Check vulnerabilities
    let vulnerabilities = cveapi::check_service_vulnerabilities(
        &service, 
        &banner, 
        !config.offline_mode
    );
    
    // Find the requested vulnerability
    vulnerabilities.into_iter().find(|v| v.id == vuln_id)
}

/// Get available hosts in a network
pub fn discover_hosts(target: &str, config: &ScanConfig) -> Vec<HostInfo> {
    let targets = resolver::resolve_targets(target);
    let host_infos = Arc::new(Mutex::new(Vec::new()));
    
    targets.par_iter().for_each(|ip| {
        let is_online = utils::ping_host(ip) || utils::tcp_ping_host(ip, config.timeout_ms);
        
        if is_online {
            let hostname = resolver::resolve_hostname_comprehensive(ip);
            
            let host_info = HostInfo {
                ip: ip.to_string(),
                hostname,
                is_online,
            };
            
            let mut host_infos_guard = host_infos.lock().unwrap();
            host_infos_guard.push(host_info);
        }
    });
    
    Arc::try_unwrap(host_infos)
        .unwrap()
        .into_inner()
        .unwrap()
}

/// Generate a summary of vulnerabilities from scan results
fn generate_vulnerability_summary(ports: &[PortResult]) -> crate::models::VulnerabilitySummary {
    use std::collections::HashMap;
    
    // Initialize counters
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;
    let mut actively_exploited_count = 0;
    let mut exploit_available_count = 0;
    
    // Initialize category and vector maps
    let mut categories: HashMap<String, usize> = HashMap::new();
    let mut attack_vectors: HashMap<String, usize> = HashMap::new();
    let mut mitre_tactics: HashMap<String, usize> = HashMap::new();
    
    // Recommendations to return based on findings
    let mut recommendations = Vec::new();
    
    // Analyze all vulnerabilities across all ports
    for port in ports {
        for vuln in &port.vulnerabilities {
            // Count by severity
            if let Some(severity) = &vuln.severity {
                match severity.to_uppercase().as_str() {
                    "CRITICAL" => critical_count += 1,
                    "HIGH" => high_count += 1,
                    "MEDIUM" => medium_count += 1,
                    "LOW" => low_count += 1,
                    _ => info_count += 1,
                }
            } else if let Some(score) = vuln.cvss_score {
                // Categorize by CVSS score if no explicit severity
                if score >= 9.0 { critical_count += 1; }
                else if score >= 7.0 { high_count += 1; }
                else if score >= 4.0 { medium_count += 1; }
                else if score >= 0.1 { low_count += 1; }
                else { info_count += 1; }
            } else {
                // No severity or score means we treat it as informational
                info_count += 1;
            }
            
            // Count actively exploited vulnerabilities
            if vuln.actively_exploited.unwrap_or(false) {
                actively_exploited_count += 1;
            }
            
            // Count vulnerabilities with available exploits
            if vuln.exploit_available.unwrap_or(false) {
                exploit_available_count += 1;
            }
            
            // Count by category
            if let Some(category) = &vuln.category {
                *categories.entry(category.clone()).or_insert(0) += 1;
            }
            
            // Count by attack vector
            if let Some(vector) = &vuln.attack_vector {
                *attack_vectors.entry(vector.clone()).or_insert(0) += 1;
            }
            
            // Count by MITRE ATT&CK tactics
            if let Some(tactics) = &vuln.mitre_tactics {
                for tactic in tactics {
                    *mitre_tactics.entry(tactic.clone()).or_insert(0) += 1;
                }
            }
            
            // Collect mitigation recommendations if available
            if let Some(mitigation) = &vuln.mitigation {
                if !recommendations.contains(mitigation) {
                    recommendations.push(mitigation.clone());
                }
            }
        }
    }
    
    // If we don't have enough recommendations, add generic ones based on findings
    if recommendations.is_empty() {
        if actively_exploited_count > 0 {
            recommendations.push("Prioritize patching vulnerabilities with known exploits in the wild".to_string());
        }
        if critical_count > 0 || high_count > 0 {
            recommendations.push("Address critical and high severity vulnerabilities immediately".to_string());
        }
        if attack_vectors.contains_key("Web") {
            recommendations.push("Implement Web Application Firewall (WAF) to protect web services".to_string());
        }
        if attack_vectors.contains_key("Network") {
            recommendations.push("Review network segmentation and firewall rules".to_string());
        }
        if attack_vectors.contains_key("OT/ICS") {
            recommendations.push("Apply OT/ICS security best practices including network isolation".to_string());
        }
    }
    
    // Limit to top 5 recommendations
    if recommendations.len() > 5 {
        recommendations.truncate(5);
    }
    
    // Calculate a basic risk score (0-10)
    let total_count = critical_count + high_count + medium_count + low_count + info_count;
    let weighted_score = if total_count > 0 {
        (critical_count as f32 * 10.0 + high_count as f32 * 7.0 + medium_count as f32 * 4.0 + low_count as f32 * 1.0) / total_count as f32
    } else {
        0.0
    };
    
    // Apply modifier for actively exploited vulnerabilities
    let exploit_modifier = if actively_exploited_count > 0 {
        1.0 + (actively_exploited_count as f32 * 0.2).min(1.0)  // Max 20% increase
    } else {
        1.0
    };
    
    let overall_risk_score = (weighted_score * exploit_modifier).min(10.0);
    
    crate::models::VulnerabilitySummary {
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        actively_exploited_count,
        exploit_available_count,
        overall_risk_score,
        top_recommendations: recommendations,
        categories,
        attack_vectors,
        mitre_tactics,
    }
}
