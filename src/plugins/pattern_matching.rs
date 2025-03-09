// Pattern Matching Vulnerability Detector Plugin

use std::error::Error;
use crate::models::{Vulnerability, ScanConfig};
use crate::plugins::VulnerabilityDetectorPlugin;
use crate::cveapi;

pub struct PatternMatchingPlugin {
    enabled: bool,
}

impl PatternMatchingPlugin {
    pub fn new() -> Self {
        Self {
            enabled: true,
        }
    }
}

impl VulnerabilityDetectorPlugin for PatternMatchingPlugin {
    fn name(&self) -> &str {
        "Pattern Matching Vulnerability Detector"
    }
    
    fn description(&self) -> &str {
        "Detects vulnerabilities using pattern matching against known vulnerability signatures"
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
        // This uses the existing offline vulnerability pattern matching
        let vulnerabilities = cveapi::match_offline_vulnerabilities(service, banner);
        Ok(vulnerabilities)
    }
    
    fn lookup_vulnerability(&self, 
                           identifier: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
        // Pattern matching is not designed for direct vulnerability lookups
        // It works on service banners, not vulnerability IDs
        Ok(None)
    }
}
