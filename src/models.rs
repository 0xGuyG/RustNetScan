// Author: CyberCraft Alchemist
// Data models for the network vulnerability scanner

use serde::{Deserialize, Serialize};

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
}
