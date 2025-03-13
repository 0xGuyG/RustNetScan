// ICS-CERT (Industrial Control Systems Cyber Emergency Response Team) Vulnerability Detector Plugin

use std::error::Error;
use crate::models::{Vulnerability, ScanConfig};
use crate::plugins::VulnerabilityDetectorPlugin;
use crate::cveapi;

pub struct IcsCertDetectorPlugin {
    enabled: bool,
}

impl IcsCertDetectorPlugin {
    pub fn new() -> Self {
        Self {
            enabled: true,
        }
    }
    
    // Helper method to determine if a service might be an industrial control system
    fn is_ics_service(&self, service: &str) -> bool {
        let ics_keywords = [
            "modbus", "dnp3", "bacnet", "ethernet/ip", "profinet", 
            "s7", "siemens", "rockwell", "allen-bradley", "scada", 
            "plc", "hmi", "ics", "industrial"
        ];
        
        ics_keywords.iter().any(|&keyword| service.to_lowercase().contains(keyword))
    }
}

impl VulnerabilityDetectorPlugin for IcsCertDetectorPlugin {
    fn name(&self) -> &str {
        "ICS-CERT Vulnerability Detector"
    }
    
    fn description(&self) -> &str {
        "Detects vulnerabilities in Industrial Control Systems using ICS-CERT advisories"
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    fn detect_vulnerabilities(&self, 
                             service: &str, 
                             _banner: &str, 
                             config: &ScanConfig) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        // Skip if not an ICS service or if offline mode is enabled
        if !self.is_ics_service(service) || config.offline_mode {
            return Ok(Vec::new());
        }
        
        // In a real implementation, this would query ICS-CERT advisories
        // For now, we'll return a limited set of known ICS vulnerabilities when we detect ICS systems
        
        let mut vulnerabilities = Vec::new();
        
        // Check for common ICS vulnerabilities based on service and banner
        if service.to_lowercase().contains("modbus") {
            // Example Modbus vulnerability
            vulnerabilities.push(cveapi::create_full_vulnerability(
                "ICS-VU-923731".to_string(),
                "Modbus protocol lacks authentication mechanisms allowing unauthorized commands".to_string(),
                Some("High".to_string()),
                Some(8.2),
                Some(vec!["https://ics-cert.us-cert.gov/advisories/ICSA-18-240-01".to_string()]),
                Some(true),  // Actively exploited
                Some(true),  // Exploit available
                Some("Implement Modbus security extensions or use a secure VPN tunnel".to_string()),
                Some("OT/ICS Vulnerability".to_string()),
                Some("CWE-306".to_string()),  // Missing Authentication
                Some("OT/ICS".to_string()),
                Some(vec!["Initial Access".to_string(), "Execution".to_string()]),
                Some(vec!["T1190".to_string(), "T1195".to_string()])
            ));
        }
        
        if service.to_lowercase().contains("bacnet") {
            // Example BACnet vulnerability
            vulnerabilities.push(cveapi::create_full_vulnerability(
                "ICS-VU-587142".to_string(),
                "BACnet protocol allows unauthenticated device discovery and manipulation".to_string(),
                Some("High".to_string()),
                Some(7.8),
                Some(vec!["https://ics-cert.us-cert.gov/advisories/ICSA-17-138-01".to_string()]),
                Some(true),  // Actively exploited
                Some(true),  // Exploit available
                Some("Isolate BACnet networks from public networks using firewalls".to_string()),
                Some("OT/ICS Vulnerability".to_string()),
                Some("CWE-306".to_string()),  // Missing Authentication
                Some("OT/ICS".to_string()),
                Some(vec!["Discovery".to_string(), "Lateral Movement".to_string()]),
                Some(vec!["T1120".to_string(), "T1210".to_string()])
            ));
        }
        
        Ok(vulnerabilities)
    }
    
    fn lookup_vulnerability(&self, 
                           identifier: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
        // Only process ICS-VU or ICSA identifiers
        if !identifier.starts_with("ICS-VU-") && !identifier.starts_with("ICSA-") {
            return Ok(None);
        }
        
        // In a real implementation, this would query the ICS-CERT database
        // For now, we'll return None as this would be implemented later
        Ok(None)
    }
}
