// NVD (National Vulnerability Database) Vulnerability Detector Plugin

use std::error::Error;
use crate::models::{Vulnerability, ScanConfig};
use crate::plugins::VulnerabilityDetectorPlugin;
use crate::cveapi;

pub struct NvdDetectorPlugin {
    enabled: bool,
}

impl NvdDetectorPlugin {
    pub fn new() -> Self {
        Self {
            enabled: true,
        }
    }
}

impl VulnerabilityDetectorPlugin for NvdDetectorPlugin {
    fn name(&self) -> &str {
        "NVD Vulnerability Detector"
    }
    
    fn description(&self) -> &str {
        "Detects vulnerabilities using the National Vulnerability Database (NVD)"
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
        // If offline mode is enabled, don't perform NVD lookups
        if config.offline_mode {
            return Ok(Vec::new());
        }
        
        // Use the existing cveapi functionality to detect vulnerabilities
        let vulnerabilities = cveapi::check_service_vulnerabilities(service, banner, true);
        Ok(vulnerabilities)
    }
    
    fn lookup_vulnerability(&self, 
                           identifier: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
        // Use the existing cveapi functionality to lookup a vulnerability
        cveapi::lookup_vulnerability(identifier)
    }
}
