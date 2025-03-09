// Vulnerability Detector Plugin Architecture
// This module provides a pluggable architecture for vulnerability detection

use std::error::Error;
use crate::models::{Vulnerability, ScanConfig};

/// Trait defining the interface for vulnerability detector plugins
pub trait VulnerabilityDetectorPlugin {
    /// Returns the name of the plugin
    fn name(&self) -> &str;
    
    /// Returns a description of the plugin
    fn description(&self) -> &str;
    
    /// Returns the version of the plugin
    fn version(&self) -> &str;
    
    /// Returns true if the plugin is enabled
    fn is_enabled(&self) -> bool;
    
    /// Detects vulnerabilities based on service information and banner
    fn detect_vulnerabilities(&self, 
                             service: &str, 
                             banner: &str, 
                             config: &ScanConfig) -> Result<Vec<Vulnerability>, Box<dyn Error>>;
    
    /// Performs direct vulnerability lookup by identifier (e.g., CVE ID)
    fn lookup_vulnerability(&self, 
                           identifier: &str) -> Result<Option<Vulnerability>, Box<dyn Error>>;
}

// Re-export specific plugin modules
pub mod nvd;
pub mod circl;
pub mod ics_cert;
pub mod mitre;
pub mod pattern_matching;

// Plugin registry to manage available detector plugins
pub struct PluginRegistry {
    plugins: Vec<Box<dyn VulnerabilityDetectorPlugin>>,
}

impl PluginRegistry {
    /// Create a new plugin registry with default plugins
    pub fn new() -> Self {
        let mut registry = Self { 
            plugins: Vec::new(),
        };
        
        // Register default plugins
        registry.register_plugin(Box::new(nvd::NvdDetectorPlugin::new()));
        registry.register_plugin(Box::new(circl::CirclDetectorPlugin::new()));
        registry.register_plugin(Box::new(pattern_matching::PatternMatchingPlugin::new()));
        
        // Optional plugins based on configuration
        registry.register_plugin(Box::new(ics_cert::IcsCertDetectorPlugin::new()));
        registry.register_plugin(Box::new(mitre::MitreAttackPlugin::new()));
        
        registry
    }
    
    /// Register a new plugin
    pub fn register_plugin(&mut self, plugin: Box<dyn VulnerabilityDetectorPlugin>) {
        self.plugins.push(plugin);
    }
    
    /// Get all registered plugins
    pub fn get_plugins(&self) -> &[Box<dyn VulnerabilityDetectorPlugin>] {
        &self.plugins
    }
    
    /// Get enabled plugins
    pub fn get_enabled_plugins(&self) -> Vec<&Box<dyn VulnerabilityDetectorPlugin>> {
        self.plugins.iter()
            .filter(|p| p.is_enabled())
            .collect()
    }
    
    /// Detect vulnerabilities using all enabled plugins
    pub fn detect_vulnerabilities(&self, 
                                 service: &str, 
                                 banner: &str, 
                                 config: &ScanConfig) -> Vec<Vulnerability> {
        let mut results = Vec::new();
        
        for plugin in self.get_enabled_plugins() {
            if let Ok(vulnerabilities) = plugin.detect_vulnerabilities(service, banner, config) {
                results.extend(vulnerabilities);
            }
        }
        
        // Deduplicate vulnerabilities by ID
        results.sort_by(|a, b| a.id.cmp(&b.id));
        results.dedup_by(|a, b| a.id == b.id);
        
        results
    }
    
    /// Lookup vulnerability using all enabled plugins
    pub fn lookup_vulnerability(&self, 
                              identifier: &str) -> Result<Option<Vulnerability>, Box<dyn Error>> {
        for plugin in self.get_enabled_plugins() {
            if let Ok(Some(vulnerability)) = plugin.lookup_vulnerability(identifier) {
                return Ok(Some(vulnerability));
            }
        }
        
        Ok(None)
    }
}
