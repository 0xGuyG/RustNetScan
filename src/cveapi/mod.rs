// Author: CyberCraft Alchemist
// CVE database API and vulnerability detection functionalities - Main module

// Re-export all public components
pub use self::cache::{init_cve_cache, get_from_cache, add_to_cache};
pub use self::lookup::{lookup_vulnerability, lookup_vulnerability_nvd, lookup_vulnerability_mitre, lookup_vulnerability_circl};
pub use self::detection::{check_service_vulnerabilities, match_offline_vulnerabilities, check_known_service_vulnerabilities};
pub use self::enrichment::{check_exploit_db, check_active_exploitation, map_to_mitre_attack, lookup_cwe_for_cve};
pub use self::models::{create_vulnerability, create_full_vulnerability, categorize_vulnerability, determine_attack_vector};
pub use self::attack_path::{generate_attack_paths, extract_service_from_vulnerability, calculate_impact, 
                          generate_mitigations, build_attack_progression, get_technique_for_vulnerability, 
                          generate_data_exfiltration_path, generate_lateral_movement_path, generate_ics_attack_path};

// Submodules
mod cache;
mod lookup;
mod detection;
mod enrichment;
mod models;
mod attack_path;
