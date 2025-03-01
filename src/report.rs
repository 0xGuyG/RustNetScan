// Author: CyberCraft Alchemist
// Report generation functionalities in multiple formats

use std::fs;
use std::io::{self, Write};
use chrono::Local;

use crate::models::ScanResult;

/// Generate a text report of the scanning results
pub fn generate_text_report(results: &[ScanResult], filename: &str) -> io::Result<()> {
    let mut file = fs::File::create(filename)?;
    
    // Header
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file, "{:^80}", "NETWORK VULNERABILITY SCAN REPORT")?;
    writeln!(file, "{:^80}", Local::now().format("%Y-%m-%d %H:%M:%S").to_string())?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    // Summary
    let total_hosts = results.len();
    let total_ports = results.iter().map(|r| r.open_ports.len()).sum::<usize>();
    let total_vulns = results.iter()
        .flat_map(|r| &r.open_ports)
        .map(|p| p.vulnerabilities.len())
        .sum::<usize>();
    
    writeln!(file, "SUMMARY")?;
    writeln!(file, "Total hosts scanned: {}", total_hosts)?;
    writeln!(file, "Total open ports found: {}", total_ports)?;
    writeln!(file, "Total potential vulnerabilities detected: {}", total_vulns)?;
    writeln!(file)?;
    
    // Detailed results
    writeln!(file, "DETAILED RESULTS")?;
    writeln!(file)?;
    
    for result in results {
        writeln!(file, "{}", "-".repeat(80))?;
        
        // Include hostname if different from IP
        if result.hostname != result.host {
            writeln!(file, "Host: {} ({})", result.hostname, result.host)?;
        } else {
            writeln!(file, "Host: {}", result.host)?;
        }
        
        writeln!(file, "Scan Time: {}", result.scan_time)?;
        writeln!(file, "Open Ports: {}", result.open_ports.len())?;
        writeln!(file)?;
        
        for port_result in &result.open_ports {
            writeln!(file, "  Port: {} ({})", port_result.port, port_result.service)?;
            writeln!(file, "  Banner: {}", port_result.banner)?;
            
            if !port_result.vulnerabilities.is_empty() {
                writeln!(file, "  Potential Vulnerabilities:")?;
                for vuln in &port_result.vulnerabilities {
                    // Include severity and CVSS if available
                    let severity_info = match &vuln.severity {
                        Some(severity) => {
                            if let Some(score) = vuln.cvss_score {
                                format!(" [{}] (CVSS: {:.1})", severity, score)
                            } else {
                                format!(" [{}]", severity)
                            }
                        },
                        None => "".to_string()
                    };
                    
                    writeln!(file, "    - {}{}: {}", vuln.id, severity_info, vuln.description)?;
                    
                    // Include references if available
                    if let Some(refs) = &vuln.references {
                        if !refs.is_empty() {
                            writeln!(file, "      References:")?;
                            for reference in refs.iter().take(3) {  // Limit to first 3 references
                                writeln!(file, "        {}", reference)?;
                            }
                        }
                    }
                }
            } else {
                writeln!(file, "  No known vulnerabilities detected")?;
            }
            
            writeln!(file)?;
        }
    }
    
    // Footer
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file, "End of Report")?;
    writeln!(file, "{}", "=".repeat(80))?;
    
    Ok(())
}

/// Generate an HTML report of the scanning results
pub fn generate_html_report(results: &[ScanResult], filename: &str) -> io::Result<()> {
    let mut file = fs::File::create(filename)?;
    
    // Begin HTML with enhanced styling for vulnerabilities
    write!(file, r#"<!DOCTYPE html>
<html>
<head>
    <title>Network Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .host {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 15px; }}
        .port {{ background-color: #ffffff; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin-bottom: 10px; }}
        .vulnerability {{ background-color: #fff3cd; padding: 10px; border-radius: 5px; margin-top: 10px; }}
        h1, h2, h3 {{ color: #343a40; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background-color: #e9ecef; }}
        .hostname {{ color: #212529; font-weight: bold; }}
        .ip-address {{ color: #6c757d; font-size: 0.9em; }}
        
        /* Enhanced vulnerability styling */
        .critical-severity {{ background-color: #dc3545; color: white; padding: 2px 6px; border-radius: 4px; }}
        .high-severity {{ background-color: #fd7e14; color: white; padding: 2px 6px; border-radius: 4px; }}
        .medium-severity {{ background-color: #ffc107; color: black; padding: 2px 6px; border-radius: 4px; }}
        .low-severity {{ background-color: #6c757d; color: white; padding: 2px 6px; border-radius: 4px; }}
        .unknown-severity {{ background-color: #17a2b8; color: white; padding: 2px 6px; border-radius: 4px; }}
        .cve-id {{ font-family: monospace; font-weight: bold; }}
        .vuln-details {{ margin-left: 20px; margin-top: 5px; }}
        .references {{ font-size: 0.9em; margin-top: 5px; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Vulnerability Scan Report</h1>
            <p>Generated on: {}</p>
        </div>
"#, Local::now().format("%Y-%m-%d %H:%M:%S").to_string())?;
    
    // Summary
    let total_hosts = results.len();
    let total_ports = results.iter().map(|r| r.open_ports.len()).sum::<usize>();
    let total_vulns = results.iter()
        .flat_map(|r| &r.open_ports)
        .map(|p| p.vulnerabilities.len())
        .sum::<usize>();
    
    let critical_vulns = count_vulnerabilities_by_severity(results, "critical");
    let high_vulns = count_vulnerabilities_by_severity(results, "high");
    let medium_vulns = count_vulnerabilities_by_severity(results, "medium");
    let low_vulns = count_vulnerabilities_by_severity(results, "low");
    
    write!(file, r#"
        <div class="summary">
            <h2>Summary</h2>
            <table>
                <tr><th>Total hosts scanned</th><td>{}</td></tr>
                <tr><th>Total open ports found</th><td>{}</td></tr>
                <tr><th>Total vulnerabilities detected</th><td>{}</td></tr>
            </table>
            
            <h3>Vulnerability Breakdown</h3>
            <table>
                <tr><th>Critical</th><td><span class="critical-severity">{}</span></td></tr>
                <tr><th>High</th><td><span class="high-severity">{}</span></td></tr>
                <tr><th>Medium</th><td><span class="medium-severity">{}</span></td></tr>
                <tr><th>Low</th><td><span class="low-severity">{}</span></td></tr>
                <tr><th>Unknown</th><td><span class="unknown-severity">{}</span></td></tr>
            </table>
        </div>
        
        <h2>Detailed Results</h2>
"#, total_hosts, total_ports, total_vulns, 
    critical_vulns, high_vulns, medium_vulns, low_vulns, 
    total_vulns - (critical_vulns + high_vulns + medium_vulns + low_vulns))?;
    
    // Detailed results
    for result in results {
        write!(file, r#"
        <div class="host">
"#)?;

        // Display hostname if different from IP
        if result.hostname != result.host {
            write!(file, r#"
            <h3><span class="hostname">{}</span> <span class="ip-address">({})</span></h3>
"#, html_escape(&result.hostname), html_escape(&result.host))?;
        } else {
            write!(file, r#"
            <h3><span class="hostname">{}</span></h3>
"#, html_escape(&result.host))?;
        }

        write!(file, r#"
            <p>Scan Time: {}</p>
            <p>Open Ports: {}</p>
            
"#, result.scan_time, result.open_ports.len())?;
        
        for port_result in &result.open_ports {
            write!(file, r#"
            <div class="port">
                <strong>Port: {} ({})</strong>
                <p>Banner: {}</p>
"#, port_result.port, html_escape(&port_result.service), html_escape(&port_result.banner))?;
            
            if !port_result.vulnerabilities.is_empty() {
                write!(file, r#"
                <div class="vulnerability">
                    <h4>Potential Vulnerabilities:</h4>
                    <ul>
"#)?;
                
                for vuln in &port_result.vulnerabilities {
                    // Determine severity class
                    let severity_class = match &vuln.severity {
                        Some(sev) if sev.to_lowercase() == "critical" => "critical-severity",
                        Some(sev) if sev.to_lowercase() == "high" => "high-severity",
                        Some(sev) if sev.to_lowercase() == "medium" => "medium-severity",
                        Some(sev) if sev.to_lowercase() == "low" => "low-severity",
                        _ => "unknown-severity",
                    };
                    
                    // Format severity and CVSS information
                    let severity_info = match &vuln.severity {
                        Some(severity) => {
                            if let Some(score) = vuln.cvss_score {
                                format!("<span class=\"{}\">{}:</span> (CVSS: {:.1})", 
                                        severity_class, severity, score)
                            } else {
                                format!("<span class=\"{}\">{}:</span>", severity_class, severity)
                            }
                        },
                        None => String::from("<span class=\"unknown-severity\">Unknown</span>")
                    };
                    
                    write!(file, r#"
                        <li>
                            <div><strong class="cve-id">{}</strong> {}</div>
                            <div class="vuln-details">{}</div>
"#, html_escape(&vuln.id), severity_info, html_escape(&vuln.description))?;
                    
                    // Include references if available
                    if let Some(refs) = &vuln.references {
                        if !refs.is_empty() {
                            write!(file, r#"
                            <div class="references">
                                References:
                                <ul>
"#)?;
                            
                            for reference in refs.iter().take(3) {  // Limit to first 3 references
                                write!(file, r#"
                                    <li><a href="{}" target="_blank">{}</a></li>
"#, html_escape(reference), html_escape(reference))?;
                            }
                            
                            write!(file, r#"
                                </ul>
                            </div>
"#)?;
                        }
                    }
                    
                    write!(file, r#"
                        </li>
"#)?;
                }
                
                write!(file, r#"
                    </ul>
                </div>
"#)?;
            } else {
                write!(file, r#"
                <p>No known vulnerabilities detected.</p>
"#)?;
            }
            
            write!(file, r#"
            </div>
"#)?;
        }
        
        write!(file, r#"
        </div>
"#)?;
    }
    
    // Close the HTML document
    write!(file, r#"
        <div class="footer" style="margin-top: 20px; text-align: center; color: #6c757d;">
            <p>Rust Network Vulnerability Scanner v1.0.0</p>
        </div>
    </div>
</body>
</html>
"#)?;
    
    Ok(())
}

/// Generate a JSON report of the scanning results
pub fn generate_json_report(results: &[ScanResult], filename: &str) -> io::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    fs::write(filename, json)?;
    Ok(())
}

/// Count vulnerabilities by severity level
fn count_vulnerabilities_by_severity(results: &[ScanResult], severity: &str) -> usize {
    results.iter()
        .flat_map(|r| &r.open_ports)
        .flat_map(|p| &p.vulnerabilities)
        .filter(|v| v.severity.as_ref().map_or(false, |s| s.to_lowercase() == severity))
        .count()
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}
