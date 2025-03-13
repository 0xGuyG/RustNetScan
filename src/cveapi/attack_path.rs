// Author: CyberCraft Alchemist
// Attack path generation and analysis module for RustNetScan

use std::collections::HashMap;
use crate::models::{Vulnerability, AttackPath, AttackStep};

/// Generate attack paths based on discovered vulnerabilities
pub fn generate_attack_paths(vulnerabilities: &[Vulnerability]) -> Vec<AttackPath> {
    let mut attack_paths = Vec::new();
    
    // Group vulnerabilities by category for easier path generation
    let mut categorized_vulns: HashMap<String, Vec<&Vulnerability>> = HashMap::new();
    for vuln in vulnerabilities {
        if let Some(category) = &vuln.category {
            categorized_vulns.entry(category.clone()).or_insert_with(Vec::new).push(vuln);
        }
    }
    
    // Create paths for web vulnerabilities
    if let Some(web_vulns) = categorized_vulns.get("Web Application") {
        if !web_vulns.is_empty() {
            let mut steps = Vec::new();
            let mut vuln_ids = Vec::new();
            
            // Get the vuln IDs for reference
            for vuln in web_vulns {
                vuln_ids.push(vuln.id.clone());
            }
            
            steps.push(AttackStep {
                description: "Initial Access: Web Application Vulnerability".to_string(),
                vulnerabilities: vuln_ids.clone(),
                mitre_technique: Some("T1190".to_string()),
            });
            
            // Check for specific vulnerability types that could lead to code execution
            if web_vulns.iter().any(|v| v.id.contains("SQL") || v.description.contains("SQL")) {
                steps.push(AttackStep {
                    description: "Lateral Movement: Database Access via SQL Injection".to_string(),
                    vulnerabilities: web_vulns.iter()
                        .filter(|v| v.id.contains("SQL") || v.description.contains("SQL"))
                        .map(|v| v.id.clone())
                        .collect(),
                    mitre_technique: Some("T1190".to_string()),
                });
            }
            
            if web_vulns.iter().any(|v| v.id.contains("XSS") || v.description.contains("Cross-site")) {
                steps.push(AttackStep {
                    description: "Credential Access: Session Hijacking via XSS".to_string(),
                    vulnerabilities: web_vulns.iter()
                        .filter(|v| v.id.contains("XSS") || v.description.contains("Cross-site"))
                        .map(|v| v.id.clone())
                        .collect(),
                    mitre_technique: Some("T1059.007".to_string()),
                });
            }
            
            if web_vulns.iter().any(|v| v.id.contains("RCE") || v.description.contains("Remote Code")) {
                steps.push(AttackStep {
                    description: "Execution: Remote Code Execution".to_string(),
                    vulnerabilities: web_vulns.iter()
                        .filter(|v| v.id.contains("RCE") || v.description.contains("Remote Code"))
                        .map(|v| v.id.clone())
                        .collect(),
                    mitre_technique: Some("T1203".to_string()),
                });
                
                steps.push(AttackStep {
                    description: "Privilege Escalation: System Access".to_string(),
                    vulnerabilities: web_vulns.iter()
                        .filter(|v| v.id.contains("RCE") || v.description.contains("Remote Code"))
                        .map(|v| v.id.clone())
                        .collect(),
                    mitre_technique: Some("T1068".to_string()),
                });
            }
            
            if !steps.is_empty() {
                attack_paths.push(AttackPath {
                    entry_point: "Web Application".to_string(),
                    steps,
                    impact: "Critical - Potential for data breach and system compromise".to_string(),
                    likelihood: "High".to_string(),
                    mitigations: vec!["Apply security patches".to_string(), "Implement WAF".to_string(), "Use input validation".to_string()],
                });
            }
        }
    }
    
    // Create paths for industrial control systems
    if let Some(ics_vulns) = categorized_vulns.get("Industrial Control System") {
        if !ics_vulns.is_empty() {
            let mut steps = Vec::new();
            let mut vuln_ids = Vec::new();
            
            // Get the vuln IDs for reference
            for vuln in ics_vulns {
                vuln_ids.push(vuln.id.clone());
            }
            
            steps.push(AttackStep {
                description: "Initial Access: ICS Protocol Vulnerability".to_string(),
                vulnerabilities: vuln_ids.clone(),
                mitre_technique: Some("T0886".to_string()),
            });
            
            steps.push(AttackStep {
                description: "Discovery: ICS Enumeration".to_string(),
                vulnerabilities: vuln_ids.clone(),
                mitre_technique: Some("T0846".to_string()),
            });
            
            if ics_vulns.iter().any(|v| v.description.contains("authentication") || v.description.contains("Authorization")) {
                let auth_vuln_ids: Vec<String> = ics_vulns.iter()
                    .filter(|v| v.description.contains("authentication") || v.description.contains("Authorization"))
                    .map(|v| v.id.clone())
                    .collect();
                
                steps.push(AttackStep {
                    description: "Defense Evasion: Authentication Bypass".to_string(),
                    vulnerabilities: auth_vuln_ids.clone(),
                    mitre_technique: Some("T0859".to_string()),
                });
                
                steps.push(AttackStep {
                    description: "Execution: Unauthorized Command Execution".to_string(),
                    vulnerabilities: auth_vuln_ids.clone(),
                    mitre_technique: Some("T0831".to_string()),
                });
                
                steps.push(AttackStep {
                    description: "Impact: Process Manipulation".to_string(),
                    vulnerabilities: auth_vuln_ids,
                    mitre_technique: Some("T0831".to_string()),
                });
            }
            
            attack_paths.push(AttackPath {
                entry_point: "Industrial Control System".to_string(),
                steps,
                impact: "Critical - Potential for physical damage or operational disruption".to_string(),
                likelihood: "Medium".to_string(),
                mitigations: vec!["Network segmentation".to_string(), "Access control".to_string(), "ICS-specific monitoring".to_string()],
            });
        }
    }
    
    // Add default attack path for remote access vulnerabilities
    if let Some(remote_vulns) = categorized_vulns.get("Remote Access") {
        if !remote_vulns.is_empty() {
            let mut steps = Vec::new();
            let mut vuln_ids = Vec::new();
            
            // Get the vuln IDs for reference
            for vuln in remote_vulns {
                vuln_ids.push(vuln.id.clone());
            }
            
            steps.push(AttackStep {
                description: "Initial Access: Remote Service Exploitation".to_string(),
                vulnerabilities: vuln_ids.clone(),
                mitre_technique: Some("T1133".to_string()),
            });
            
            steps.push(AttackStep {
                description: "Execution: Command-Line Interface".to_string(),
                vulnerabilities: vuln_ids.clone(),
                mitre_technique: Some("T1059".to_string()),
            });
            
            steps.push(AttackStep {
                description: "Persistence: Create Account".to_string(),
                vulnerabilities: vuln_ids.clone(),
                mitre_technique: Some("T1136".to_string()),
            });
            
            steps.push(AttackStep {
                description: "Privilege Escalation: Exploitation for Privilege Escalation".to_string(),
                vulnerabilities: vuln_ids,
                mitre_technique: Some("T1068".to_string()),
            });
            
            attack_paths.push(AttackPath {
                entry_point: "Remote Service".to_string(),
                steps,
                impact: "High - Potential for system compromise and data theft".to_string(),
                likelihood: "High".to_string(),
                mitigations: vec!["Patch systems".to_string(), "Use strong authentication".to_string(), "Network segmentation".to_string()],
            });
        }
    }
    
    attack_paths
}

/// Extract service type from vulnerability data
pub fn extract_service_from_vulnerability(vuln: &Vulnerability) -> Option<String> {
    if let Some(attack_vector) = &vuln.attack_vector {
        match attack_vector.as_str() {
            "Web" => Some("Web Service".to_string()),
            "Remote Access" => Some("Remote Access Service".to_string()),
            "File Transfer" => Some("File Transfer Service".to_string()),
            "Network Management" => Some("Network Management Service".to_string()),
            "Industrial Control Protocol" => Some("ICS Service".to_string()),
            _ => None,
        }
    } else {
        None
    }
}

/// Calculate potential impact of vulnerability exploitation
pub fn calculate_impact(vuln: &Vulnerability) -> String {
    if let Some(cvss) = vuln.cvss_score {
        if cvss >= 9.0 {
            return "Critical Impact: Potential for complete system compromise and data breach".to_string();
        } else if cvss >= 7.0 {
            return "High Impact: Significant security breach and system access".to_string();
        } else if cvss >= 4.0 {
            return "Medium Impact: Limited system access or data exposure".to_string();
        } else {
            return "Low Impact: Minor security implications".to_string();
        }
    }
    
    // If no CVSS score, use category to estimate impact
    if let Some(category) = &vuln.category {
        match category.as_str() {
            "Industrial Control System" => "Critical Impact: Potential for physical damage or operational disruption".to_string(),
            "Web Application" => "High Impact: Potential for data breach or system compromise".to_string(),
            "Remote Access" => "High Impact: Direct system access for attackers".to_string(),
            _ => "Medium Impact: Potential security implications".to_string(),
        }
    } else {
        "Unknown Impact: Insufficient data to determine impact".to_string()
    }
}

/// Generate mitigation recommendations
pub fn generate_mitigations(vuln: &Vulnerability) -> Vec<String> {
    let mut mitigations = Vec::new();
    
    // Add any already-defined mitigation
    if let Some(mitigation) = &vuln.mitigation {
        mitigations.push(mitigation.clone());
    }
    
    // Add category-specific mitigations
    if let Some(category) = &vuln.category {
        match category.as_str() {
            "Web Application" => {
                mitigations.push("Implement input validation and output encoding".to_string());
                mitigations.push("Keep web application frameworks and libraries updated".to_string());
                mitigations.push("Use a Web Application Firewall (WAF)".to_string());
            },
            "Remote Access" => {
                mitigations.push("Implement multi-factor authentication".to_string());
                mitigations.push("Use VPN for remote access".to_string());
                mitigations.push("Limit access to required users only".to_string());
            },
            "Industrial Control System" => {
                mitigations.push("Implement network segmentation for ICS networks".to_string());
                mitigations.push("Deploy ICS-specific monitoring and intrusion detection".to_string());
                mitigations.push("Implement secure-by-design protocols where possible".to_string());
            },
            _ => {
                mitigations.push("Apply security patches and updates regularly".to_string());
                mitigations.push("Implement defense-in-depth security controls".to_string());
            }
        }
    }
    
    mitigations
}

/// Build a detailed attack progression
pub fn build_attack_progression(vulnerabilities: &[Vulnerability]) -> Vec<String> {
    let mut progression = Vec::new();
    
    // Sort vulnerabilities by severity (if available)
    let mut sorted_vulns = vulnerabilities.to_vec();
    sorted_vulns.sort_by(|a, b| {
        let a_score = a.cvss_score.unwrap_or(0.0);
        let b_score = b.cvss_score.unwrap_or(0.0);
        b_score.partial_cmp(&a_score).unwrap()
    });
    
    // Build progression based on severity and type
    for vuln in &sorted_vulns {
        if let Some(attack_vector) = &vuln.attack_vector {
            match attack_vector.as_str() {
                "Web" => {
                    progression.push("Initial Access: Web application vulnerability exploitation".to_string());
                    if vuln.description.contains("SQL") {
                        progression.push("Collection: Database data access".to_string());
                    }
                    if vuln.description.contains("XSS") {
                        progression.push("Credential Access: User session hijacking".to_string());
                    }
                    if vuln.description.contains("RCE") || vuln.description.contains("Remote Code") {
                        progression.push("Execution: Remote code execution on web server".to_string());
                    }
                },
                "Remote Access" => {
                    progression.push("Initial Access: Remote service exploitation".to_string());
                    progression.push("Execution: Command execution via remote access".to_string());
                    progression.push("Persistence: Creation of backdoor access".to_string());
                },
                "Industrial Control Protocol" => {
                    progression.push("Initial Access: Industrial protocol exploitation".to_string());
                    progression.push("Discovery: ICS component enumeration".to_string());
                    progression.push("Impact: Manipulation of industrial processes".to_string());
                },
                _ => {
                    progression.push(format!("Exploitation of {} vulnerability", attack_vector));
                }
            }
        }
    }
    
    // Remove duplicates while maintaining order
    let mut unique_progression = Vec::new();
    for step in progression {
        if !unique_progression.contains(&step) {
            unique_progression.push(step);
        }
    }
    
    unique_progression
}

/// Get MITRE ATT&CK technique for a vulnerability
pub fn get_technique_for_vulnerability(vuln: &Vulnerability) -> Option<String> {
    if let Some(techniques) = &vuln.mitre_techniques {
        if !techniques.is_empty() {
            return Some(techniques[0].clone());
        }
    }
    
    // If no technique is directly associated, try to infer based on category or description
    if let Some(category) = &vuln.category {
        match category.as_str() {
            "Web Application" => Some("T1190 - Exploit Public-Facing Application".to_string()),
            "Remote Access" => Some("T1133 - External Remote Services".to_string()),
            "Industrial Control System" => Some("T0831 - Manipulation of Control".to_string()),
            _ => None,
        }
    } else {
        None
    }
}

/// Generate a data exfiltration path based on vulnerabilities
pub fn generate_data_exfiltration_path(vulnerabilities: &[Vulnerability]) -> Option<AttackPath> {
    // Check if we have vulnerabilities that could lead to data exfiltration
    let has_data_access = vulnerabilities.iter().any(|v| {
        v.description.contains("SQL") || 
        v.description.contains("XSS") || 
        v.description.contains("RCE") ||
        v.description.contains("File Inclusion")
    });
    
    if has_data_access {
        let vuln_ids: Vec<String> = vulnerabilities.iter()
            .filter(|v| {
                v.description.contains("SQL") || 
                v.description.contains("XSS") || 
                v.description.contains("RCE") ||
                v.description.contains("File Inclusion")
            })
            .map(|v| v.id.clone())
            .collect();
        
        let mut steps = Vec::new();
        
        steps.push(AttackStep {
            description: "Initial Access: Exploiting identified vulnerability".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T1190".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Collection: Data from Local System".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T1005".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Command and Control: Establish communication channel".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T1071".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Exfiltration: Data transfer to attacker-controlled system".to_string(),
            vulnerabilities: vuln_ids,
            mitre_technique: Some("T1048".to_string()),
        });
        
        let mitigations = vulnerabilities.iter()
            .flat_map(|v| generate_mitigations(v))
            .collect::<Vec<String>>();
        
        Some(AttackPath {
            entry_point: "Web Application or Service Vulnerability".to_string(),
            steps,
            impact: "Critical - Data Exfiltration".to_string(),
            likelihood: "Medium".to_string(),
            mitigations,
        })
    } else {
        None
    }
}

/// Generate a lateral movement path
pub fn generate_lateral_movement_path(vulnerabilities: &[Vulnerability]) -> Option<AttackPath> {
    // Check if we have vulnerabilities that could lead to lateral movement
    let has_lateral_potential = vulnerabilities.iter().any(|v| {
        v.description.contains("RCE") || 
        v.description.contains("Privilege") || 
        v.attack_vector.as_ref().map_or(false, |av| av == "Remote Access")
    });
    
    if has_lateral_potential {
        let vuln_ids: Vec<String> = vulnerabilities.iter()
            .filter(|v| {
                v.description.contains("RCE") || 
                v.description.contains("Privilege") || 
                v.attack_vector.as_ref().map_or(false, |av| av == "Remote Access")
            })
            .map(|v| v.id.clone())
            .collect();
        
        let mut steps = Vec::new();
        
        steps.push(AttackStep {
            description: "Initial Access: Exploiting vulnerability for system access".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T1190".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Discovery: Network service scanning".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T1046".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Lateral Movement: Internal spearphishing or exploitation".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T1534".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Execution: Remote service exploitation".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T1569".to_string()),
        });
        
        let mitigations = vulnerabilities.iter()
            .flat_map(|v| generate_mitigations(v))
            .collect::<Vec<String>>();
        
        Some(AttackPath {
            entry_point: "Remote Service Vulnerability".to_string(),
            steps,
            impact: "Critical - Lateral Movement".to_string(),
            likelihood: "High".to_string(),
            mitigations,
        })
    } else {
        None
    }
}

/// Generate specific ICS attack path
pub fn generate_ics_attack_path(vulnerabilities: &[Vulnerability]) -> Option<AttackPath> {
    // Check if we have ICS-related vulnerabilities
    let has_ics_vulns = vulnerabilities.iter().any(|v| {
        v.category.as_ref().map_or(false, |c| c.contains("Industrial")) ||
        v.attack_vector.as_ref().map_or(false, |av| av.contains("Industrial")) ||
        v.description.contains("PLC") ||
        v.description.contains("SCADA") ||
        v.description.contains("ICS")
    });
    
    if has_ics_vulns {
        let vuln_ids: Vec<String> = vulnerabilities.iter()
            .filter(|v| {
                v.category.as_ref().map_or(false, |c| c.contains("Industrial")) ||
                v.attack_vector.as_ref().map_or(false, |av| av.contains("Industrial")) ||
                v.description.contains("PLC") ||
                v.description.contains("SCADA") ||
                v.description.contains("ICS")
            })
            .map(|v| v.id.clone())
            .collect();
        
        let mut steps = Vec::new();
        
        steps.push(AttackStep {
            description: "Initial Access: Exploitation of industrial protocol vulnerability".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T0866".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Discovery: Enumeration of industrial control devices".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T0846".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Lateral Movement: Pivot to engineering workstations".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T0859".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Collection: SCADA data collection".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T0802".to_string()),
        });
        
        steps.push(AttackStep {
            description: "Impact: Manipulation of industrial process".to_string(),
            vulnerabilities: vuln_ids.clone(),
            mitre_technique: Some("T0831".to_string()),
        });
        
        let mitigations = vulnerabilities.iter()
            .flat_map(|v| generate_mitigations(v))
            .collect::<Vec<String>>();
        
        Some(AttackPath {
            entry_point: "Industrial Control System Vulnerability".to_string(),
            steps,
            impact: "Critical - Physical Process Manipulation".to_string(),
            likelihood: "Medium".to_string(),
            mitigations,
        })
    } else {
        None
    }
}
