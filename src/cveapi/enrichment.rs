// Vulnerability enrichment functionality

use std::error::Error;
use std::time::Duration;
use reqwest::blocking::Client;
use serde_json::Value;
use crate::constants::MITRE_ATTACK_MAPPINGS;

/// Add exploit database integration
pub fn check_exploit_db(cve_id: &str) -> Result<Option<Vec<String>>, Box<dyn Error>> {
    // Initialize the HTTP client
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    // Query ExploitDB API
    let url = format!("https://www.exploit-db.com/search?cve={}", cve_id);
    
    let response = match client.get(&url).send() {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(_) => return Ok(None), // No successful response
        Err(_) => return Ok(None), // Error in request, treat as no exploits found
    };
    
    let response_text = match response.text() {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };
    
    // Check if there are exploits (simplified check)
    if response_text.contains("No results") || !response_text.contains(cve_id) {
        return Ok(None);
    }
    
    // Extract exploit links (this is a simplified approach)
    let exploits = vec![
        format!("https://www.exploit-db.com/search?cve={}", cve_id),
        // In a real implementation, we would parse actual exploit URLs from the response
    ];
    
    // Try to get additional exploits from other sources
    if let Ok(Some(mut other_exploits)) = check_metasploit_exploits(cve_id) {
        exploits.iter().for_each(|e| other_exploits.push(e.clone()));
        return Ok(Some(other_exploits));
    }
    
    Ok(Some(exploits))
}

/// Check for Metasploit exploits
fn check_metasploit_exploits(cve_id: &str) -> Result<Option<Vec<String>>, Box<dyn Error>> {
    // This is a simplified implementation - in a real-world scenario, 
    // we would query Metasploit's database or a public API
    
    // For now, return None to indicate no exploits found
    Ok(None)
}

/// Function to check if a vulnerability is actively exploited in the wild
pub fn check_active_exploitation(cve_id: &str) -> Result<bool, Box<dyn Error>> {
    // Initialize the HTTP client
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    // Query CISA Known Exploited Vulnerabilities Catalog (KEV)
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    
    let response = match client.get(url).send() {
        Ok(resp) if resp.status().is_success() => resp,
        _ => return Ok(false), // Assume not actively exploited if we can't check
    };
    
    let kev_json: Value = match response.json() {
        Ok(json) => json,
        Err(_) => return Ok(false),
    };
    
    // Check if the CVE is in the KEV catalog
    if let Some(vulnerabilities) = kev_json.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulnerabilities {
            if let Some(id) = vuln.get("cveID").and_then(|id| id.as_str()) {
                if id == cve_id {
                    return Ok(true);
                }
            }
        }
    }
    
    Ok(false)
}

/// Map a CVE to MITRE ATT&CK tactics and techniques
pub fn map_to_mitre_attack(cve_id: &str) -> Result<(Option<Vec<String>>, Option<Vec<String>>), Box<dyn Error>> {
    // Check if we have a direct mapping in our constants
    for mapping in MITRE_ATTACK_MAPPINGS {
        if mapping.cve_pattern.is_empty() || cve_id.contains(mapping.cve_pattern) {
            return Ok((
                Some(mapping.tactics.split(',').map(String::from).collect()),
                Some(mapping.techniques.split(',').map(String::from).collect())
            ));
        }
    }
    
    // If no direct mapping, try to determine based on CVE description
    // In a real implementation, we would perform NLP or other analysis to map
    // the vulnerability to MITRE ATT&CK tactics and techniques
    
    // For now, attempt to get this information from an API or database
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    // Example API call - in reality you would use a proper API for this
    let url = format!("https://example.com/api/mitre-mapping/{}", cve_id);
    
    let response = match client.get(&url).send() {
        Ok(resp) if resp.status().is_success() => resp,
        _ => return Ok((None, None)), // No mapping found
    };
    
    let mapping_json: Value = match response.json() {
        Ok(json) => json,
        Err(_) => return Ok((None, None)),
    };
    
    // Extract tactics and techniques from the response
    let tactics = mapping_json.get("tactics")
        .and_then(|t| t.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
    
    let techniques = mapping_json.get("techniques")
        .and_then(|t| t.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
    
    Ok((tactics, techniques))
}

/// Lookup CWE for a given CVE
pub fn lookup_cwe_for_cve(cve_id: &str) -> Result<Option<String>, Box<dyn Error>> {
    // Initialize the HTTP client
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    // Query NVD API for CWE information
    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
    
    let response = match client.get(&url).send() {
        Ok(resp) if resp.status().is_success() => resp,
        _ => return Ok(None), // No CWE information available
    };
    
    let nvd_json: Value = match response.json() {
        Ok(json) => json,
        Err(_) => return Ok(None),
    };
    
    // Try to extract CWE from the response
    if let Some(vulnerabilities) = nvd_json.get("result").and_then(|r| r.get("CVE_Items")).and_then(|i| i.as_array()) {
        if let Some(vuln) = vulnerabilities.first() {
            if let Some(cwe_nodes) = vuln.get("cve").and_then(|c| c.get("problemtype")).and_then(|p| p.get("problemtype_data")).and_then(|d| d.as_array()) {
                if let Some(cwe_node) = cwe_nodes.first() {
                    if let Some(descriptions) = cwe_node.get("description").and_then(|d| d.as_array()) {
                        if let Some(description) = descriptions.first() {
                            if let Some(cwe) = description.get("value").and_then(|v| v.as_str()) {
                                return Ok(Some(cwe.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(None)
}
