// Author: CyberCraft Alchemist
// Data models for the network vulnerability scanner

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Structure to represent host information with both IP and hostname
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub ip: String,
    pub hostname: String,
    pub is_online: bool,
}

// Structure to represent a scan result for a host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,         // IP address 
    pub hostname: String,     // Resolved hostname
    pub is_online: bool,      // Whether the host is online
    pub open_ports: Vec<PortResult>,
    pub scan_time: String,
    pub os_info: Option<String>, // Operating system information
    pub vulnerabilities_summary: Option<VulnerabilitySummary>, // Overall vulnerability summary
    pub attack_paths: Option<Vec<AttackPath>>, // Potential attack paths
}

// Structure to represent a port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub service: String,
    pub banner: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

// Structure to represent a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub description: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f32>,
    pub references: Option<Vec<String>>,
    pub actively_exploited: Option<bool>, // New field indicating if vulnerability is actively exploited
    pub exploit_available: Option<bool>,  // New field indicating if public exploits are available
    pub mitigation: Option<String>,       // New field suggesting mitigation strategies
    pub category: Option<String>,         // Vulnerability category (e.g., "Injection", "Broken Authentication")
    pub cwe_id: Option<String>,           // Common Weakness Enumeration ID
    pub attack_vector: Option<String>,    // How the vulnerability can be exploited
    pub mitre_tactics: Option<Vec<String>>, // MITRE ATT&CK tactics this vulnerability relates to
    pub mitre_techniques: Option<Vec<String>>, // MITRE ATT&CK techniques this vulnerability enables
}

// Structure for scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub threads: usize,
    pub timeout_ms: u64,
    pub randomize_scan: bool,
    pub verbose: bool,
    pub offline_mode: bool,
    pub output_format: String,
    pub scan_offline_hosts: bool,
    pub enhanced_vuln_detection: bool,    // Enable additional vulnerability detection methods
    pub assess_attack_surface: bool,      // Perform additional attack surface analysis
    pub check_misconfigurations: bool,    // Check for common security misconfigurations
    pub check_default_credentials: bool,  // Check for default credentials
    pub mitre_mapping: bool,              // Map vulnerabilities to MITRE ATT&CK framework
    pub attack_path_analysis: bool,       // Analyze potential attack paths
}

// Structure to summarize vulnerability findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub actively_exploited_count: usize,
    pub exploit_available_count: usize,
    pub overall_risk_score: f32,          // Calculated risk score based on findings
    pub top_recommendations: Vec<String>, // Top security recommendations
    pub categories: HashMap<String, usize>, // Counts of vulnerabilities by category
    pub attack_vectors: HashMap<String, usize>, // Counts of vulnerabilities by attack vector
    pub mitre_tactics: HashMap<String, usize>,  // Counts of MITRE ATT&CK tactics
}

// Structure for misconfigurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Misconfiguration {
    pub category: String,
    pub description: String,
    pub severity: String,
    pub recommendation: String,
}

// Structure for attack surface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub exposed_services: Vec<String>,
    pub potential_entry_points: Vec<String>,
    pub risky_configurations: Vec<String>,
}

// Structure for representing a potential attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub entry_point: String,
    pub steps: Vec<AttackStep>,
    pub impact: String,
    pub likelihood: String,
    pub mitigations: Vec<String>,
}

// Structure for representing a step in an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub description: String,
    pub vulnerabilities: Vec<String>,
    pub mitre_technique: Option<String>,
}
