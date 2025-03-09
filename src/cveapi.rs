// Author: CyberCraft Alchemist
// CVE database API and vulnerability detection functionalities

use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;
use crate::models::{Vulnerability, AttackPath, AttackStep};
use crate::constants::{VULNERABILITY_PATTERNS, MITRE_ATTACK_MAPPINGS};
use regex::Regex;

//=============================================================================
// SECTION: CACHE MANAGEMENT
//=============================================================================

// Cache to store previously retrieved CVE data
static mut CVE_CACHE: Option<HashMap<String, Vulnerability>> = None;

/// Initialize the CVE cache
#[allow(static_mut_refs)]
pub fn init_cve_cache() {
    unsafe {
        if CVE_CACHE.is_none() {
            CVE_CACHE = Some(HashMap::new());
        }
    }
}

/// Get a vulnerability from the cache
#[allow(static_mut_refs)]
fn get_from_cache(cve_id: &str) -> Option<Vulnerability> {
    unsafe {
        if let Some(cache) = &CVE_CACHE {
            return cache.get(cve_id).cloned();
        }
    }
    None
}

/// Add a vulnerability to the cache
#[allow(static_mut_refs)]
fn add_to_cache(cve_id: String, vulnerability: Vulnerability) {
    unsafe {
        if let Some(cache) = &mut CVE_CACHE {
            cache.insert(cve_id, vulnerability);
        }
    }
}

//=============================================================================
// SECTION: VULNERABILITY LOOKUP API
//=============================================================================

/// Lookup vulnerability information from the NVD API
pub fn lookup_vulnerability(cve_id: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
    // First check if we have this CVE in our cache
    if let Some(cached_vuln) = get_from_cache(cve_id) {
        return Ok(Some(cached_vuln));
    }

    // Define a client with reasonable timeout
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Try NVD API first
    match lookup_vulnerability_nvd(&client, cve_id) {
        Ok(Some(mut vuln)) => {
            // Check for exploit information and active exploitation
            let exploit_info = check_exploit_db(cve_id).unwrap_or(None);
            let is_active_threat = check_active_exploitation(cve_id).unwrap_or(false);
            
            // Add MITRE ATT&CK mapping
            if let Ok(mapping) = map_to_mitre_attack(cve_id) {
                vuln.mitre_tactics = mapping.0;
                vuln.mitre_techniques = mapping.1;
            }
            
            // Check for CWE information
            if let Ok(Some(cwe_id)) = lookup_cwe_for_cve(cve_id) {
                vuln.cwe_id = Some(cwe_id);
            }
            
            // Update vulnerability with exploit info
            vuln.actively_exploited = Some(is_active_threat);
            vuln.exploit_available = Some(exploit_info.is_some());
            
            // If actively exploited, update description and severity
            if is_active_threat {
                vuln.description = format!("[ACTIVELY EXPLOITED] {}", vuln.description);
                // Upgrade severity if actively exploited
                if let Some(ref current_severity) = vuln.severity {
                    if current_severity != "CRITICAL" {
                        vuln.severity = Some("CRITICAL".to_string());
                    }
                }
            }
            
            // Add exploit links to references if available
            if let Some(exploit_links) = exploit_info {
                if let Some(ref mut refs) = vuln.references {
                    for link in exploit_links {
                        refs.push(link);
                    }
                } else {
                    vuln.references = Some(exploit_links);
                }
            }
            
            // Cache the enhanced result before returning
            add_to_cache(cve_id.to_string(), vuln.clone());
            Ok(Some(vuln))
        },
        Ok(None) => {
            // Try MITRE CVE first, then fall back to CIRCL CVE API
            match lookup_vulnerability_mitre(&client, cve_id) {
                Ok(Some(vuln)) => {
                    // Cache the result before returning
                    add_to_cache(cve_id.to_string(), vuln.clone());
                    Ok(Some(vuln))
                },
                Ok(None) => {
                    // Fall back to CIRCL CVE API
                    match lookup_vulnerability_circl(&client, cve_id) {
                        Ok(Some(vuln)) => {
                            // Cache the result before returning
                            add_to_cache(cve_id.to_string(), vuln.clone());
                            Ok(Some(vuln))
                        },
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    }
                },
                Err(e) => Err(e),
            }
        },
        Err(e) => Err(e),
    }
}

//=============================================================================
// SECTION: DATA STRUCTURES
//=============================================================================

/// Data structures for NVD API response
#[derive(Deserialize)]
struct NvdResponse {
    result: NvdResult,
}

#[derive(Deserialize)]
struct NvdResult {
    cve_items: Vec<NvdCveItem>,
}

#[derive(Deserialize)]
struct NvdCveItem {
    cve: NvdCve,
    impact: Option<NvdImpact>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct NvdCve {
    id: String,
    descriptions: Vec<NvdDescription>,
    references: Option<Vec<NvdReference>>,
}

#[derive(Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Deserialize)]
struct NvdReference {
    url: String,
}

#[derive(Deserialize)]
struct NvdImpact {
    base_metric_v3: Option<NvdBaseMetricV3>,
    base_metric_v2: Option<NvdBaseMetricV2>,
}

#[derive(Deserialize)]
struct NvdBaseMetricV3 {
    cvss_v3: NvdCvssV3,
}

#[derive(Deserialize)]
struct NvdCvssV3 {
    base_score: f32,
    base_severity: String,
}

#[derive(Deserialize)]
struct NvdBaseMetricV2 {
    cvss_v2: NvdCvssV2,
    severity: String,
}

#[derive(Deserialize)]
struct NvdCvssV2 {
    base_score: f32,
}

/// Lookup vulnerability information from the MITRE CVE database
fn lookup_vulnerability_mitre(client: &Client, cve_id: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
    // MITRE CVE API URL
    let url = format!("https://cveawg.mitre.org/api/cve/{}", cve_id);
    
    let response = client.get(&url)
        .header("User-Agent", "RustNetScan-Vulnerability-Scanner/1.0")
        .send()?;
    
    if !response.status().is_success() {
        return Ok(None);
    }
    
    let mitre_response: Value = serde_json::from_str(&response.text()?)?;
    
    // Extract data from MITRE response
    if let Some(cve_data) = mitre_response.get("containers").and_then(|c| c.get("cna")) {
        let description = cve_data.get("descriptions")
            .and_then(|descs| descs.get(0))
            .and_then(|desc| desc.get("value"))
            .and_then(|val| val.as_str())
            .unwrap_or("No description available");
        
        // Construct references if available
        let references = cve_data.get("references")
            .and_then(|refs| refs.as_array())
            .map(|refs_array| {
                refs_array.iter()
                    .filter_map(|r| r.get("url").and_then(|u| u.as_str()).map(String::from))
                    .collect::<Vec<String>>()
            });
        
        // Create Vulnerability object
        let vulnerability = Vulnerability {
            id: cve_id.to_string(),
            description: description.to_string(),
            severity: None, // MITRE doesn't provide severity directly
            cvss_score: None, // MITRE doesn't provide CVSS directly
            references,
            actively_exploited: None,
            exploit_available: None,
            mitigation: None,
            category: None,
            cwe_id: None,
            attack_vector: None,
            mitre_tactics: None,
            mitre_techniques: None,
        };
        
        return Ok(Some(vulnerability));
    }
    
    Ok(None)
}

/// Lookup vulnerability through NVD API
fn lookup_vulnerability_nvd(client: &Client, cve_id: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
    let url = format!("https://services.nvd.nist.gov/rest/json/cve/1.0/{}", cve_id);
    
    let response = client.get(&url)
        .header("User-Agent", "RustNetScan-Vulnerability-Scanner/1.0")
        .send()?;
    
    if !response.status().is_success() {
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        return Err(format!("NVD API error: {}", response.status()).into());
    }
    
    let nvd_response: NvdResponse = response.json()?;
    
    if nvd_response.result.cve_items.is_empty() {
        return Ok(None);
    }
    
    let cve_item = &nvd_response.result.cve_items[0];
    
    // Extract English description
    let description = cve_item.cve.descriptions.iter()
        .find(|d| d.lang == "en")
        .map_or("No description available", |d| &d.value);
    
    // Extract CVE references
    let references = cve_item.cve.references.as_ref().map(|refs| {
        refs.iter().map(|r| r.url.clone()).collect::<Vec<String>>()
    });
    
    // Extract severity and CVSS score (prefer V3 over V2)
    let (severity, cvss_score) = if let Some(impact) = &cve_item.impact {
        if let Some(ref v3) = impact.base_metric_v3 {
            (Some(v3.cvss_v3.base_severity.clone()), Some(v3.cvss_v3.base_score))
        } else if let Some(ref v2) = impact.base_metric_v2 {
            (Some(v2.severity.clone()), Some(v2.cvss_v2.base_score))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    
    let vulnerability = Vulnerability {
        id: cve_id.to_string(),
        description: description.to_string(),
        severity,
        cvss_score,
        references,
        actively_exploited: None,
        exploit_available: None,
        mitigation: None,
        category: None,
        cwe_id: None,
        attack_vector: None,
        mitre_tactics: None,
        mitre_techniques: None,
    };
    
    Ok(Some(vulnerability))
}

/// Data structures for CIRCL CVE API response
#[derive(Deserialize)]
struct CirclCveResponse {
    id: String,
    summary: String,
    references: Vec<String>,
    cvss: Option<f32>,
}

/// Lookup vulnerability through CIRCL CVE API
fn lookup_vulnerability_circl(client: &Client, cve_id: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
    let url = format!("https://cve.circl.lu/api/cve/{}", cve_id);
    
    let response = client.get(&url)
        .header("User-Agent", "RustNetScan-Vulnerability-Scanner/1.0")
        .send()?;
    
    if !response.status().is_success() {
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        return Err(format!("CIRCL API error: {}", response.status()).into());
    }
    
    let circl_response: CirclCveResponse = response.json()?;
    
    // Determine severity based on CVSS score
    let (severity, cvss_score) = if let Some(score) = circl_response.cvss {
        let severity = if score >= 9.0 {
            "Critical"
        } else if score >= 7.0 {
            "High"
        } else if score >= 4.0 {
            "Medium"
        } else {
            "Low"
        };
        
        (Some(severity.to_string()), Some(score))
    } else {
        (None, None)
    };
    
    let vulnerability = Vulnerability {
        id: circl_response.id,
        description: circl_response.summary,
        severity,
        cvss_score,
        references: Some(circl_response.references),
        actively_exploited: None,
        exploit_available: None,
        mitigation: None,
        category: None,
        cwe_id: None,
        attack_vector: None,
        mitre_tactics: None,
        mitre_techniques: None,
    };
    
    Ok(Some(vulnerability))
}

/// Create a new vulnerability object with all fields properly initialized
pub fn create_vulnerability(id: String, description: String, severity: Option<String>, cvss_score: Option<f32>, references: Option<Vec<String>>) -> Vulnerability {
    Vulnerability {
        id,
        description,
        severity,
        cvss_score,
        references,
        actively_exploited: None,
        exploit_available: None,
        mitigation: None,
        category: None,
        cwe_id: None,
        attack_vector: None,
        mitre_tactics: None,
        mitre_techniques: None,
    }
}

/// Create a fully populated vulnerability object
pub fn create_full_vulnerability(
    id: String,
    description: String,
    severity: Option<String>,
    cvss_score: Option<f32>,
    references: Option<Vec<String>>,
    actively_exploited: Option<bool>,
    exploit_available: Option<bool>,
    mitigation: Option<String>,
    category: Option<String>,
    cwe_id: Option<String>,
    attack_vector: Option<String>,
    mitre_tactics: Option<Vec<String>>,
    mitre_techniques: Option<Vec<String>>
) -> Vulnerability {
    Vulnerability {
        id,
        description,
        severity,
        cvss_score,
        references,
        actively_exploited,
        exploit_available,
        mitigation,
        category,
        cwe_id,
        attack_vector,
        mitre_tactics,
        mitre_techniques,
    }
}

/// Match a service banner against offline vulnerability patterns
pub fn match_offline_vulnerabilities(service: &str, banner: &str) -> Vec<Vulnerability> {
    let mut vulnerabilities = Vec::new();
    
    for (service_pattern, regex, vuln_id, vuln_desc) in VULNERABILITY_PATTERNS.iter() {
        // Check if this pattern applies to our service
        if service.contains(service_pattern) && regex.is_match(banner) {
            vulnerabilities.push(Vulnerability {
                id: vuln_id.clone(),
                description: vuln_desc.clone(),
                severity: Some("High".to_string()),
                cvss_score: Some(7.5), // Default medium-high score
                references: Some(vec![format!("Detected via pattern matching: {}", regex.as_str())]),
                actively_exploited: Some(false),
                exploit_available: Some(false),
                mitigation: None,
                category: Some(categorize_vulnerability(vuln_id)),
                cwe_id: None,
                attack_vector: Some(determine_attack_vector(service, banner)),
                mitre_tactics: None,
                mitre_techniques: None,
            });
        }
    }
    
    vulnerabilities
}

// Add exploit database integration
pub fn check_exploit_db(cve_id: &str) -> Result<Option<Vec<String>>, Box<dyn Error>> {
    // Define a client with reasonable timeout
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    
    let url = format!("https://www.exploit-db.com/search?cve={}", cve_id);
    
    let response = client.get(&url)
        .header("User-Agent", "RustNetScan-Vulnerability-Scanner/1.0")
        .send()?;
    
    if !response.status().is_success() {
        return Ok(None);
    }
    
    // Get the response body
    let body = response.text()?;
    
    // Parse for exploit information
    // This is a simple implementation - in production, this would use proper HTML parsing
    let mut exploit_links = Vec::new();
    
    // Check if any exploits were found
    if body.contains("class=\"exploitTableDescription\"") {
        // Add the exploit database link
        exploit_links.push(url);
        
        // You could extract individual exploit links here with proper HTML parsing
        // For now, just add a generic link to the exploit database
        exploit_links.push(format!("https://www.exploit-db.com/exploits/{}", cve_id.replace("CVE-", "")));
    }
    
    if exploit_links.is_empty() {
        return Ok(None);
    }
    
    Ok(Some(exploit_links))
}

// Function to check if a vulnerability is actively exploited in the wild
pub fn check_active_exploitation(cve_id: &str) -> Result<bool, Box<dyn Error>> {
    // List of known actively exploited vulnerabilities - this would be updated regularly
    // In production, this should be fetched from a regularly updated source
    let actively_exploited = [
        "CVE-2021-44228", // Log4Shell
        "CVE-2021-26855", // ProxyLogon
        "CVE-2021-34527", // PrintNightmare
        "CVE-2019-19781", // Citrix ADC
        "CVE-2019-0708",  // BlueKeep
        // Add more as needed
    ];
    
    Ok(actively_exploited.contains(&cve_id))
}

/// Determine the category of a vulnerability
pub fn categorize_vulnerability(vuln_id: &str) -> String {
    // This is a simplified implementation
    // In production, this would involve a more comprehensive lookup
    if vuln_id.contains("SQL") || vuln_id.contains("INJECTION") {
        return "Injection".to_string();
    } else if vuln_id.contains("XSS") {
        return "Cross-Site Scripting".to_string();
    } else if vuln_id.contains("AUTH") || vuln_id.contains("CRED") {
        return "Authentication".to_string();
    } else if vuln_id.contains("CSRF") {
        return "Cross-Site Request Forgery".to_string();
    } else if vuln_id.contains("SSRF") {
        return "Server-Side Request Forgery".to_string();
    } else if vuln_id.contains("OVERFLOW") || vuln_id.contains("BOF") {
        return "Buffer Overflow".to_string();
    } else if vuln_id.contains("DOS") || vuln_id.contains("DENIAL") {
        return "Denial of Service".to_string();
    } else if vuln_id.contains("BYPASS") {
        return "Security Bypass".to_string();
    } else if vuln_id.contains("PRIV") || vuln_id.contains("ESCALATION") {
        return "Privilege Escalation".to_string();
    } else if vuln_id.contains("INFO") || vuln_id.contains("DISCLOSURE") {
        return "Information Disclosure".to_string();
    } else if vuln_id.contains("EXEC") || vuln_id.contains("RCE") {
        return "Remote Code Execution".to_string();
    } else if vuln_id.contains("OT-") || vuln_id.contains("ICS") {
        return "OT/ICS Vulnerability".to_string();
    }
    
    // Default category
    "Unspecified".to_string()
}

/// Determine the attack vector based on service and banner
pub fn determine_attack_vector(service: &str, banner: &str) -> String {
    // Determine attack vector based on service type
    match service.to_lowercase().as_str() {
        s if s.contains("http") || s.contains("web") => "Web".to_string(),
        s if s.contains("ssh") => "SSH".to_string(),
        s if s.contains("ftp") => "FTP".to_string(),
        s if s.contains("smb") || s.contains("cifs") => "SMB/CIFS".to_string(),
        s if s.contains("rdp") => "RDP".to_string(),
        s if s.contains("telnet") => "Telnet".to_string(),
        s if s.contains("smtp") || s.contains("mail") => "Email".to_string(),
        s if s.contains("dns") => "DNS".to_string(),
        s if s.contains("snmp") => "SNMP".to_string(),
        s if s.contains("modbus") || s.contains("bacnet") || s.contains("dnp3") => "OT/ICS".to_string(),
        s if s.contains("database") || s.contains("sql") || s.contains("mysql") || s.contains("postgres") => "Database".to_string(),
        _ => "Network".to_string() // Default to network
    }
}

/// Map a CVE to MITRE ATT&CK tactics and techniques
pub fn map_to_mitre_attack(cve_id: &str) -> Result<(Option<Vec<String>>, Option<Vec<String>>), Box<dyn Error>> {
    // In a production environment, this would query an API or database
    // For this implementation, we'll use a small hardcoded mapping for demonstration
    
    // (CVE ID, [Tactics], [Techniques])
    // This would be replaced with a more comprehensive lookup from MITRE_ATTACK_MAPPINGS in constants.rs
    let mappings = [
        ("CVE-2021-44228", 
         vec!["Initial Access", "Execution"], 
         vec!["T1190: Exploit Public-Facing Application", "T1059: Command and Scripting Interpreter"]),
        ("CVE-2021-26855", 
         vec!["Initial Access", "Credential Access"], 
         vec!["T1190: Exploit Public-Facing Application", "T1003: OS Credential Dumping"]),
        ("CVE-2021-34527", 
         vec!["Privilege Escalation", "Execution"], 
         vec!["T1068: Exploitation for Privilege Escalation", "T1569: System Services"]),
        ("CVE-2019-19781", 
         vec!["Initial Access", "Execution"], 
         vec!["T1190: Exploit Public-Facing Application", "T1203: Exploitation for Client Execution"]),
        ("CVE-2019-0708", 
         vec!["Lateral Movement", "Execution"], 
         vec!["T1210: Exploitation of Remote Services", "T1059: Command and Scripting Interpreter"])
    ];
    
    // Look for matching CVE
    for (mapped_cve, tactics, techniques) in mappings.iter() {
        if cve_id == *mapped_cve {
            return Ok((Some(tactics.iter().map(|s| s.to_string()).collect()), 
                      Some(techniques.iter().map(|s| s.to_string()).collect())));
        }
    }
    
    // Fallback: try to determine based on vulnerability category
    // This would be enhanced in a production implementation
    Ok((None, None))
}

/// Lookup CWE for a given CVE
pub fn lookup_cwe_for_cve(cve_id: &str) -> Result<Option<String>, Box<dyn Error>> {
    // In a production environment, this would query an API or database
    // For this implementation, we'll use a small hardcoded mapping for demonstration
    let cwe_mappings = [
        ("CVE-2021-44228", "CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement"),
        ("CVE-2021-26855", "CWE-284: Improper Access Control"),
        ("CVE-2021-34527", "CWE-269: Improper Privilege Management"),
        ("CVE-2019-19781", "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"),
        ("CVE-2019-0708", "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer")
    ];
    
    // Look for matching CVE
    for (mapped_cve, cwe) in cwe_mappings.iter() {
        if cve_id == *mapped_cve {
            return Ok(Some(cwe.to_string()));
        }
    }
    
    Ok(None)
}

// Public function to perform a comprehensive vulnerability scan
pub fn check_service_vulnerabilities(
    service: &str, 
    banner: &str,
    do_api_lookup: bool
) -> Vec<Vulnerability> {
    let mut results = Vec::new();
    
    // First, check offline patterns
    let mut offline_vulns = match_offline_vulnerabilities(service, banner);
    
    // Add these to our results
    results.append(&mut offline_vulns);
    
    // If online lookup is enabled, extract potential CVE IDs from banner
    // and look them up
    if do_api_lookup {
        // This regex matches patterns like CVE-YYYY-NNNNN
        let cve_regex = regex::Regex::new(r"CVE-\d{4}-\d{4,}").unwrap();
        
        for capture in cve_regex.captures_iter(banner) {
            let cve_id = capture.get(0).unwrap().as_str();
            
            if let Ok(Some(vuln)) = lookup_vulnerability(cve_id) {
                // Check for exploit information
                let exploit_info = check_exploit_db(cve_id).unwrap_or(None);
                
                // Check if actively exploited
                let is_active_threat = check_active_exploitation(cve_id).unwrap_or(false);
                
                // Create enhanced vulnerability with exploit info
                let mut enhanced_vuln = vuln.clone();
                
                // Add exploit information to description if available
                if is_active_threat {
                    enhanced_vuln.description = format!("[ACTIVELY EXPLOITED] {}", enhanced_vuln.description);
                    // Upgrade severity if it's actively exploited
                    if enhanced_vuln.severity.is_some() {
                        let current_severity = enhanced_vuln.severity.as_ref().unwrap();
                        if current_severity != "CRITICAL" {
                            enhanced_vuln.severity = Some("CRITICAL".to_string());
                        }
                    }
                }
                
                // Add exploit links to references if available
                if let Some(exploit_links) = exploit_info {
                    if let Some(ref mut refs) = enhanced_vuln.references {
                        for link in exploit_links {
                            refs.push(link);
                        }
                    } else {
                        enhanced_vuln.references = Some(exploit_links);
                    }
                }
                
                results.push(enhanced_vuln);
            }
        }
        
        // Also check for product names and versions that might have vulnerabilities
        check_known_service_vulnerabilities(service, banner, &mut results);
    }
    
    results
}

// Check for vulnerabilities in known services based on banner information
fn check_known_service_vulnerabilities(service: &str, banner: &str, results: &mut Vec<Vulnerability>) {
    // Extract product and version information
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

/// Generate attack paths based on discovered vulnerabilities
/// Generate potential attack paths based on discovered vulnerabilities
/// Enhanced version with advanced path generation and risk scoring
pub fn generate_attack_paths(vulnerabilities: &[Vulnerability]) -> Option<Vec<AttackPath>> {
    if vulnerabilities.is_empty() {
        return None;
    }
    
    let mut attack_paths = Vec::new();
    
    // Group vulnerabilities by different aspects for multi-dimensional analysis
    let mut categorized_vulns: HashMap<String, Vec<&Vulnerability>> = HashMap::new();
    let mut service_vulns: HashMap<String, Vec<&Vulnerability>> = HashMap::new();
    let mut attack_vector_vulns: HashMap<String, Vec<&Vulnerability>> = HashMap::new();
    let mut entry_points: Vec<&Vulnerability> = Vec::new();
    
    // Calculate highest CVSS score for reference
    let max_cvss = vulnerabilities.iter()
        .filter_map(|v| v.cvss_score)
        .fold(0.0, f32::max);
    
    // Group vulnerabilities by different dimensions
    for vuln in vulnerabilities {
        // Group by category
        if let Some(cat) = &vuln.category {
            categorized_vulns.entry(cat.clone()).or_insert_with(Vec::new).push(vuln);
            
            // Identify potential entry points
            if cat == "Initial Access" || cat == "Remote Code Execution" || cat.contains("Injection") {
                entry_points.push(vuln);
            }
        }
        
        // Group by service/component (extracted from ID or description)
        let service = extract_service_from_vulnerability(vuln);
        service_vulns.entry(service).or_insert_with(Vec::new).push(vuln);
        
        // Group by attack vector
        if let Some(vector) = &vuln.attack_vector {
            attack_vector_vulns.entry(vector.clone()).or_insert_with(Vec::new).push(vuln);
        }
    }
    
    // If no clear entry points identified, use high severity vulnerabilities
    if entry_points.is_empty() {
        entry_points = vulnerabilities.iter()
            .filter(|v| {
                v.severity.as_ref().map_or(false, |s| s.to_uppercase() == "CRITICAL" || s.to_uppercase() == "HIGH") ||
                v.cvss_score.map_or(false, |score| score >= 7.0)
            })
            .collect();
    }
    
    // If still no entry points, use the highest scoring vulnerabilities
    if entry_points.is_empty() && !vulnerabilities.is_empty() {
        // Sort by severity and take top 3
        let mut sorted_vulns: Vec<&Vulnerability> = vulnerabilities.iter().collect();
        sorted_vulns.sort_by(|a, b| {
            let a_score = a.cvss_score.unwrap_or(0.0);
            let b_score = b.cvss_score.unwrap_or(0.0);
            b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        entry_points = sorted_vulns.into_iter().take(3).collect();
    }
    
    // Function to calculate likelihood based on vulnerability properties
    let calculate_likelihood = |vuln: &Vulnerability| -> (&'static str, f32) {
        let mut score = 0.0;
        
        // Base on CVSS score
        if let Some(cvss) = vuln.cvss_score {
            score += cvss / 10.0 * 0.3; // 30% weight from CVSS
        }
        
        // Increase if actively exploited
        if vuln.actively_exploited.unwrap_or(false) {
            score += 0.4; // 40% more likely if being actively exploited
        }
        
        // Increase if exploit is available
        if vuln.exploit_available.unwrap_or(false) {
            score += 0.2; // 20% more likely if exploits are available
        }
        
        // Adjust based on attack vector complexity
        if let Some(vector) = &vuln.attack_vector {
            if vector.contains("Web") {
                score += 0.1; // Web vulnerabilities often easier to exploit
            } else if vector.contains("Network") {
                score += 0.05; // Network vulnerabilities moderately accessible
            } else if vector.contains("Physical") {
                score -= 0.15; // Physical access requirements reduce likelihood
            }
        }
        
        // Cap between 0.0 and 1.0
        score = score.max(0.0).min(1.0);
        
        // Convert to categories
        match score {
            s if s >= 0.8 => ("High", score),
            s if s >= 0.5 => ("Medium", score),
            s if s >= 0.3 => ("Low", score),
            _ => ("Very Low", score)
        }
    };
    
    // Build complete attack path for each entry point
    for entry_vuln in &entry_points {
        let (likelihood_str, likelihood_score) = calculate_likelihood(entry_vuln);
        
        // Define attack path
        let mut path = AttackPath {
            entry_point: format!("Exploitation of {} vulnerability", entry_vuln.id),
            steps: Vec::new(),
            impact: calculate_impact(entry_vuln, &categorized_vulns),
            likelihood: likelihood_str.to_string(),
            mitigations: generate_mitigations(entry_vuln, &categorized_vulns),
        };
        
        // Start with the entry point step
        path.steps.push(AttackStep {
            description: format!("Exploit {} to gain initial access", entry_vuln.id),
            vulnerabilities: vec![entry_vuln.id.clone()],
            mitre_technique: entry_vuln.mitre_techniques.as_ref().and_then(|t| t.first().cloned())
                .or_else(|| get_technique_for_vulnerability(entry_vuln)),
        });
        
        // Build progression based on vulnerability types and MITRE ATT&CK stages
        build_attack_progression(&mut path, *entry_vuln, &categorized_vulns, &service_vulns, &attack_vector_vulns);
        
        attack_paths.push(path);
    }
    
    // Generate attack paths based on common attack scenarios
    // 1. Data exfiltration path
    generate_data_exfiltration_path(&mut attack_paths, &categorized_vulns);
    
    // 2. Lateral movement path
    generate_lateral_movement_path(&mut attack_paths, &categorized_vulns, &service_vulns);
    
    // 3. OT/ICS specific attack path if applicable
    generate_ics_attack_path(&mut attack_paths, &attack_vector_vulns, &categorized_vulns);
    
    if attack_paths.is_empty() {
        None
    } else {
        Some(attack_paths)
    }
}
