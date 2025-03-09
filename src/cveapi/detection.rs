// Vulnerability detection functionality

use regex::Regex;
use crate::models::Vulnerability;
use crate::constants::VULNERABILITY_PATTERNS;
use crate::cveapi::models::{create_full_vulnerability, categorize_vulnerability, determine_attack_vector};
use crate::cveapi::lookup::lookup_vulnerability;

/// Public function to perform a comprehensive vulnerability scan
pub fn check_service_vulnerabilities(
    service: &str, 
    banner: &str,
    do_api_lookup: bool
) -> Vec<Vulnerability> {
    let mut results = Vec::new();
    
    // First, try to match any offline patterns
    let offline_results = match_offline_vulnerabilities(service, banner);
    results.extend(offline_results);
    
    // Then check for known service vulnerabilities
    check_known_service_vulnerabilities(service, banner, &mut results);
    
    // If online lookup is enabled, check for any CVEs referenced in the banner
    if do_api_lookup {
        // Look for CVE patterns in banner
        if let Ok(cve_regex) = Regex::new(r"CVE-\d{4}-\d{4,}") {
            for cve_match in cve_regex.find_iter(banner) {
                let cve_id = cve_match.as_str();
                
                // Check if we already have this CVE in results
                if !results.iter().any(|v| v.id == cve_id) {
                    if let Ok(Some(vuln)) = lookup_vulnerability(cve_id) {
                        results.push(vuln);
                    }
                }
            }
        }
    }
    
    // Enhance vulnerabilities with additional metadata
    for vuln in &mut results {
        // If category is not set, try to determine it
        if vuln.category.is_none() {
            vuln.category = Some(categorize_vulnerability(&vuln.id));
        }
        
        // If attack vector is not set, determine it
        if vuln.attack_vector.is_none() {
            vuln.attack_vector = Some(determine_attack_vector(service, banner));
        }
    }
    
    results
}

/// Match a service banner against offline vulnerability patterns
pub fn match_offline_vulnerabilities(service: &str, banner: &str) -> Vec<Vulnerability> {
    let mut results = Vec::new();
    
    // Check against our predefined vulnerability patterns
    for pattern in VULNERABILITY_PATTERNS {
        if let Ok(regex) = Regex::new(pattern.regex) {
            if regex.is_match(banner) {
                let vuln = create_full_vulnerability(
                    pattern.id.to_string(),
                    pattern.description.to_string(),
                    Some(pattern.severity.to_string()),
                    Some(pattern.cvss_score),
                    Some(vec![pattern.reference.to_string()]),
                    Some(pattern.actively_exploited),
                    Some(true), // If we have a pattern, exploit is likely available
                    Some(pattern.mitigation.to_string()),
                    Some(categorize_vulnerability(pattern.id)),
                    None, // No CWE-ID for offline patterns
                    Some(determine_attack_vector(service, banner)),
                    None, // No MITRE tactics for offline patterns
                    None, // No MITRE techniques for offline patterns
                );
                
                results.push(vuln);
            }
        }
    }
    
    results
}

/// Check for vulnerabilities in known services based on banner information
pub fn check_known_service_vulnerabilities(service: &str, banner: &str, results: &mut Vec<Vulnerability>) {
    // This is a simplified example; real implementation would be more comprehensive
    let product_regexes = [
        (r"Apache/(\d+\.\d+\.\d+)", "apache_http_server"),
        (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
        (r"OpenSSH[_-](\d+\.\d+[pP]?\d*)", "openssh"),
        (r"Microsoft-IIS/(\d+\.\d+)", "iis"),
        // Add more patterns for different services
    ];
    
    for (pattern, product_name) in product_regexes.iter() {
        if let Ok(regex) = regex::Regex::new(pattern) {
            if let Some(caps) = regex.captures(banner) {
                if caps.len() > 1 {
                    let version = caps.get(1).unwrap().as_str();
                    
                    // In a real implementation, you would query a database of known vulnerabilities
                    // for this product and version. Here we just add a placeholder.
                    if product_name == &"apache_http_server" && version.starts_with("2.4.") {
                        let vuln = Vulnerability {
                            id: "PRODUCT-VULN-APACHE".to_string(),
                            description: format!("Potential vulnerabilities in Apache {} detected", version),
                            severity: Some("MEDIUM".to_string()),
                            cvss_score: Some(5.0),
                            references: Some(vec![
                                "https://httpd.apache.org/security/vulnerabilities_24.html".to_string()
                            ]),
                            actively_exploited: Some(false),
                            exploit_available: Some(true),
                            mitigation: Some("Update to the latest Apache version".to_string()),
                            category: Some("Web Server".to_string()),
                            cwe_id: None,
                            attack_vector: Some("Network".to_string()),
                            mitre_tactics: None,
                            mitre_techniques: None,
                        };
                        results.push(vuln);
                    }
                    // Add similar checks for other products
                }
            }
        }
    }
}
