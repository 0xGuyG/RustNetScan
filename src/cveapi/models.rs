// Vulnerability models and construction helpers

use crate::models::Vulnerability;

/// Create a new vulnerability object with all fields properly initialized
pub fn create_vulnerability(
    id: String, 
    description: String, 
    severity: Option<String>, 
    cvss_score: Option<f32>, 
    references: Option<Vec<String>>
) -> Vulnerability {
    create_full_vulnerability(
        id,
        description,
        severity,
        cvss_score,
        references,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

/// Create a fully populated vulnerability object
pub fn create_full_vulnerability(
    id: String,
    description: String,
    severity: Option<String>,
    cvss_score: Option<f32>,
    references: Option<Vec<String>>,
    actively_exploited: Option<bool>,
    exploit_available: Option<bool>,
    mitigation: Option<String>,
    category: Option<String>,
    cwe_id: Option<String>,
    attack_vector: Option<String>,
    mitre_tactics: Option<Vec<String>>,
    mitre_techniques: Option<Vec<String>>
) -> Vulnerability {
    Vulnerability {
        id,
        description,
        severity,
        cvss_score,
        references,
        actively_exploited,
        exploit_available,
        mitigation,
        category,
        cwe_id,
        attack_vector,
        mitre_tactics,
        mitre_techniques,
    }
}

/// Determine the category of a vulnerability
pub fn categorize_vulnerability(vuln_id: &str) -> String {
    // This is a simplified implementation that could be expanded
    if vuln_id.contains("XSS") || vuln_id.contains("CROSS-SITE") {
        "Cross-Site Scripting".to_string()
    } else if vuln_id.contains("SQL") {
        "SQL Injection".to_string()
    } else if vuln_id.contains("AUTH") || vuln_id.contains("AUTHN") {
        "Authentication".to_string()
    } else if vuln_id.contains("PRIV") || vuln_id.contains("ESCALATION") {
        "Privilege Escalation".to_string()
    } else if vuln_id.contains("RCE") || vuln_id.contains("EXEC") {
        "Remote Code Execution".to_string()
    } else if vuln_id.contains("DOS") || vuln_id.contains("DENIAL") {
        "Denial of Service".to_string()
    } else if vuln_id.contains("OVERFLOW") || vuln_id.contains("BUFFER") {
        "Buffer Overflow".to_string()
    } else if vuln_id.contains("INFO") || vuln_id.contains("DISCLOSURE") {
        "Information Disclosure".to_string()
    } else if vuln_id.contains("CSRF") || vuln_id.contains("FORGERY") {
        "Cross-Site Request Forgery".to_string()
    } else if vuln_id.contains("FILE") && (vuln_id.contains("INCLUDE") || vuln_id.contains("UPLOAD")) {
        "File Inclusion".to_string()
    } else if vuln_id.contains("TRAVERSAL") || vuln_id.contains("PATH") {
        "Path Traversal".to_string()
    } else if vuln_id.contains("ACCESS") || vuln_id.contains("CONTROL") {
        "Access Control".to_string()
    } else if vuln_id.contains("SSL") || vuln_id.contains("TLS") || vuln_id.contains("CRYPTO") {
        "Cryptographic Issue".to_string()
    } else if vuln_id.contains("ICS") || vuln_id.contains("SCADA") || vuln_id.contains("PLC") {
        "Industrial Control System".to_string()
    } else {
        "Other".to_string()
    }
}

/// Determine the attack vector based on service and banner
pub fn determine_attack_vector(service: &str, banner: &str) -> String {
    // This is a simplified implementation that could be expanded
    if service.contains("http") || service.contains("web") {
        "Web".to_string()
    } else if service.contains("ssh") || service.contains("telnet") || service.contains("rdp") {
        "Remote Access".to_string()
    } else if service.contains("ftp") || service.contains("smb") || service.contains("cifs") {
        "File Transfer".to_string()
    } else if service.contains("snmp") || service.contains("netflow") {
        "Network Management".to_string()
    } else if service.contains("modbus") || service.contains("bacnet") || service.contains("dnp3") {
        "Industrial Control Protocol".to_string()
    } else if service.contains("database") || service.contains("sql") || service.contains("oracle") {
        "Database".to_string()
    } else if service.contains("email") || service.contains("smtp") || service.contains("imap") {
        "Email".to_string()
    } else if service.contains("dns") {
        "DNS".to_string()
    } else {
        "Network".to_string()
    }
}
