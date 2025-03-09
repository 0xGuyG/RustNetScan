// Vulnerability lookup functionality

use std::error::Error;
use std::time::Duration;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;

use crate::models::Vulnerability;
use crate::cveapi::cache::{get_from_cache, add_to_cache};
use crate::cveapi::enrichment::{check_exploit_db, check_active_exploitation, map_to_mitre_attack, lookup_cwe_for_cve};

/// Lookup vulnerability information from multiple sources
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
pub fn lookup_vulnerability_mitre(client: &Client, cve_id: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
    // MITRE CVE API URL
    let url = format!("https://cveawg.mitre.org/api/cve/{}", cve_id);
    
    let response = match client.get(&url).send() {
        Ok(resp) => resp,
        Err(e) => return Err(Box::new(e)),
    };
    
    if !response.status().is_success() {
        return Ok(None); // Not found or other non-success status
    }
    
    let response_json: Value = match response.json() {
        Ok(json) => json,
        Err(e) => return Err(Box::new(e)),
    };
    
    // Extract relevant information from MITRE response
    if let Some(obj) = response_json.as_object() {
        let id = cve_id.to_string();
        
        // Extract description
        let description = obj.get("descriptions")
            .and_then(|descs| descs.as_array())
            .and_then(|descs_arr| descs_arr.iter().find(|d| d["lang"].as_str() == Some("en")))
            .and_then(|desc| desc["value"].as_str())
            .unwrap_or("No description available")
            .to_string();
        
        // References
        let references = obj.get("references")
            .and_then(|refs| refs.as_array())
            .map(|refs_arr| {
                refs_arr.iter()
                    .filter_map(|r| r["url"].as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            });
        
        // Create vulnerability
        let vuln = crate::cveapi::models::create_vulnerability(
            id,
            description,
            None, // No severity in MITRE data
            None, // No CVSS in MITRE data
            references,
        );
        
        return Ok(Some(vuln));
    }
    
    Ok(None)
}

/// Lookup vulnerability through NVD API
pub fn lookup_vulnerability_nvd(client: &Client, cve_id: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
    // NVD API URL
    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
    
    let response = match client.get(&url).send() {
        Ok(resp) => resp,
        Err(e) => return Err(Box::new(e)),
    };
    
    if !response.status().is_success() {
        return Ok(None); // Not found or other non-success status
    }
    
    let nvd_response: NvdResponse = match response.json() {
        Ok(json) => json,
        Err(e) => return Err(Box::new(e)),
    };
    
    if nvd_response.result.cve_items.is_empty() {
        return Ok(None);
    }
    
    let cve_item = &nvd_response.result.cve_items[0];
    
    // Extract description
    let description = cve_item.cve.descriptions.iter()
        .find(|d| d.lang == "en")
        .map_or("No description available", |d| &d.value)
        .to_string();
    
    // Extract references
    let references = cve_item.cve.references.as_ref().map(|refs| {
        refs.iter().map(|r| r.url.clone()).collect()
    });
    
    // Extract severity and CVSS score
    let (severity, cvss_score) = if let Some(impact) = &cve_item.impact {
        if let Some(metric_v3) = &impact.base_metric_v3 {
            (Some(metric_v3.cvss_v3.base_severity.clone()), Some(metric_v3.cvss_v3.base_score))
        } else if let Some(metric_v2) = &impact.base_metric_v2 {
            (Some(metric_v2.severity.clone()), Some(metric_v2.cvss_v2.base_score))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    
    // Create the vulnerability
    let vuln = crate::cveapi::models::create_vulnerability(
        cve_id.to_string(),
        description,
        severity,
        cvss_score,
        references,
    );
    
    Ok(Some(vuln))
}

/// Data structures for CIRCL CVE API response
#[derive(Deserialize)]
struct CirclCveResponse {
    id: String,
    summary: Option<String>,
    references: Option<Vec<String>>,
    cvss: Option<f32>,
    cvss3: Option<f32>,
}

/// Lookup vulnerability through CIRCL CVE API
pub fn lookup_vulnerability_circl(client: &Client, cve_id: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
    // CIRCL CVE API URL
    let url = format!("https://cve.circl.lu/api/cve/{}", cve_id);
    
    let response = match client.get(&url).send() {
        Ok(resp) => resp,
        Err(e) => return Err(Box::new(e)),
    };
    
    if !response.status().is_success() {
        return Ok(None); // Not found or other non-success status
    }
    
    let circl_response: CirclCveResponse = match response.json() {
        Ok(json) => json,
        Err(e) => return Err(Box::new(e)),
    };
    
    // Get description from summary
    let description = circl_response.summary
        .unwrap_or_else(|| "No description available".to_string());
    
    // Get CVSS score, preferring CVSS3 if available
    let cvss_score = circl_response.cvss3.or(circl_response.cvss);
    
    // Determine severity based on CVSS
    let severity = cvss_score.map(|score| {
        if score >= 9.0 { "CRITICAL" }
        else if score >= 7.0 { "HIGH" }
        else if score >= 4.0 { "MEDIUM" }
        else { "LOW" }
    }).map(String::from);
    
    // Create vulnerability
    let vuln = crate::cveapi::models::create_vulnerability(
        cve_id.to_string(),
        description,
        severity,
        cvss_score,
        circl_response.references,
    );
    
    Ok(Some(vuln))
}
