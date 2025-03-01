// Author: CyberCraft Alchemist
// CVE database API and vulnerability detection functionalities

use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use reqwest::blocking::Client;
use serde::Deserialize;
use crate::models::Vulnerability;
use crate::constants::VULNERABILITY_PATTERNS;

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
    };
    
    Ok(Some(vulnerability))
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
            });
        }
    }
    
    vulnerabilities
}

// Public function to perform a comprehensive vulnerability scan
pub fn check_service_vulnerabilities(
    service: &str, 
    banner: &str,
    do_api_lookup: bool
) -> Vec<Vulnerability> {
    let mut vulnerabilities = match_offline_vulnerabilities(service, banner);
    
    // If API lookup is enabled, try to get detailed info for any CVE IDs
    // found in the banner or offline matches
    if do_api_lookup {
        // First, extract any CVE IDs from the banner
        let cve_regex = regex::Regex::new(r"CVE-\d{4}-\d{4,}").unwrap();
        
        for cap in cve_regex.captures_iter(banner) {
            let cve_id = &cap[0];
            if let Ok(Some(vuln)) = lookup_vulnerability(cve_id) {
                if !vulnerabilities.iter().any(|v| v.id == cve_id) {
                    vulnerabilities.push(vuln);
                }
            }
        }
        
        // Next, enhance any CVEs from our offline patterns with API data
        for vuln in &mut vulnerabilities {
            if vuln.id.starts_with("CVE-") {
                if let Ok(Some(detailed_vuln)) = lookup_vulnerability(&vuln.id) {
                    // Update with more detailed info but preserve the match reason
                    let original_desc = vuln.description.clone();
                    *vuln = detailed_vuln;
                    vuln.description = format!("{} (Match reason: {})", vuln.description, original_desc);
                }
            }
        }
    }
    
    vulnerabilities
}
