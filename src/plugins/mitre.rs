// MITRE ATT&CK Framework Vulnerability Detector Plugin

use std::error::Error;
use crate::models::{Vulnerability, ScanConfig};
use crate::plugins::VulnerabilityDetectorPlugin;
use crate::cveapi;

pub struct MitreAttackPlugin {
    enabled: bool,
}

impl MitreAttackPlugin {
    pub fn new() -> Self {
        Self {
            enabled: true,
        }
    }
}

impl VulnerabilityDetectorPlugin for MitreAttackPlugin {
    fn name(&self) -> &str {
        "MITRE ATT&CK Vulnerability Detector"
    }
    
    fn description(&self) -> &str {
        "Maps vulnerabilities to the MITRE ATT&CK framework and enriches vulnerability data"
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    fn detect_vulnerabilities(&self, 
                             service: &str, 
                             banner: &str, 
                             config: &ScanConfig) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        // This plugin doesn't directly detect vulnerabilities
        // Instead, it enriches existing vulnerabilities with MITRE ATT&CK information
        Ok(Vec::new())
    }
    
    fn lookup_vulnerability(&self, 
                           identifier: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
        // Only process CVE identifiers
        if !identifier.starts_with("CVE-") {
            return Ok(None);
        }
        
        // Try to look up the vulnerability through other means first
        if let Ok(Some(mut vuln)) = cveapi::lookup_vulnerability(identifier) {
            // If the vulnerability exists, enrich it with MITRE ATT&CK information
            if vuln.mitre_tactics.is_none() || vuln.mitre_techniques.is_none() {
                if let Ok((tactics, techniques)) = cveapi::map_to_mitre_attack(&vuln.id) {
                    // Update the vulnerability with MITRE ATT&CK information
                    vuln.mitre_tactics = tactics;
                    vuln.mitre_techniques = techniques;
                    
                    return Ok(Some(vuln));
                }
            }
            
            return Ok(Some(vuln));
        }
        
        Ok(None)
    }
}
