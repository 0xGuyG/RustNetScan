// Author: CyberCraft Alchemist
// Command-line interface for the network vulnerability scanner

use clap::App;
use clap::Arg;
use clap::ArgMatches;
use colored::*;
use std::time::Instant;
use chrono::Local;

use rustnet_scan::models::ScanConfig;
use rustnet_scan::constants;
use rustnet_scan::cveapi;
use rustnet_scan::report;
use rustnet_scan::scanner;

#[cfg(not(debug_assertions))]
const DEFAULT_THREADS: &str = "50";
#[cfg(debug_assertions)]
const DEFAULT_THREADS: &str = "10";

fn main() {
    // Initialize CVE cache
    cveapi::init_cve_cache();
    
    // Parse command-line arguments
    let matches = parse_args();
    
    // Validate and process arguments
    let config = match build_config(&matches) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{} {}", "Error:".red().bold(), err);
            std::process::exit(1);
        }
    };
    
    // Display banner
    print_banner();
    
    // Display scan information
    println!("{} {}", "Target:".green().bold(), config.target);
    println!("{} {}", "Ports:".green().bold(), 
        if config.ports.is_empty() { "Common ports".to_string() } else { config.ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",") });
    println!("{} {}", "Threads:".green().bold(), config.threads);
    println!("{} {}", "Timeout:".green().bold(), format!("{}ms", config.timeout_ms));
    println!("{} {}", "Randomize scan:".green().bold(), config.randomize_scan);
    println!("{} {}", "Output format:".green().bold(), config.output_format);
    println!();
    
    // Record scan start time
    let start_time = Instant::now();
    
    println!("{}", "Starting network scan...".cyan().bold());
    
    // Perform the scan
    let scan_results = scanner::scan(config.clone());
    
    // Print summary
    println!("\n{} {} hosts, {} open ports, {} vulnerabilities", 
        "Found:".green().bold(),
        scan_results.len(),
        scan_results.iter().map(|r| r.open_ports.len()).sum::<usize>(),
        scan_results.iter().flat_map(|r| &r.open_ports).map(|p| p.vulnerabilities.len()).sum::<usize>()
    );
    
    // Generate report based on chosen format
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_filename = format!("scan_report_{}.{}", timestamp, config.output_format.to_lowercase());
    
    match config.output_format.as_str() {
        "TEXT" => {
            if let Err(e) = report::generate_text_report(&scan_results, &output_filename) {
                eprintln!("{} Failed to generate text report: {}", "Error:".red().bold(), e);
            }
        },
        "HTML" => {
            if let Err(e) = report::generate_html_report(&scan_results, &output_filename) {
                eprintln!("{} Failed to generate HTML report: {}", "Error:".red().bold(), e);
            }
        },
        "JSON" => {
            if let Err(e) = report::generate_json_report(&scan_results, &output_filename) {
                eprintln!("{} Failed to generate JSON report: {}", "Error:".red().bold(), e);
            }
        },
        _ => {
            eprintln!("{} Unknown output format: {}", "Error:".red().bold(), config.output_format);
        }
    }
    
    // Calculate and display scan time
    let duration = start_time.elapsed();
    println!("\n{} {:.2} seconds", "Scan completed in".green().bold(), duration.as_secs_f64());
    println!("{} {}", "Report saved to:".green().bold(), output_filename);
}

fn parse_args() -> ArgMatches<'static> {
    App::new("RustNet Scan")
        .version(constants::VERSION)
        .author("Network Security Team")
        .about("A comprehensive network vulnerability scanner written in Rust")
        .arg(Arg::with_name("target")
            .help("Target specification (IP, range, CIDR, or hostname)")
            .required(true)
            .index(1))
        .arg(Arg::with_name("ports")
            .short("p")
            .long("ports")
            .help("Ports to scan (e.g., '22,80,443' or '1-1000')")
            .takes_value(true))
        .arg(Arg::with_name("threads")
            .short("t")
            .long("threads")
            .help("Number of concurrent threads")
            .default_value(DEFAULT_THREADS)
            .takes_value(true))
        .arg(Arg::with_name("timeout")
            .short("w")
            .long("timeout")
            .help("Connection timeout in milliseconds")
            .default_value("1000")
            .takes_value(true))
        .arg(Arg::with_name("randomize")
            .short("r")
            .long("randomize")
            .help("Randomize scan order"))
        .arg(Arg::with_name("format")
            .short("f")
            .long("format")
            .help("Output format (TEXT, HTML, JSON)")
            .default_value("TEXT")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .help("Output file")
            .takes_value(true))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Verbose output"))
        .arg(Arg::with_name("offline")
            .long("offline")
            .help("Offline mode - don't query online CVE databases"))
        .arg(Arg::with_name("scan-offline")
            .long("scan-offline")
            .help("Scan hosts even if they don't respond to ping"))
        .get_matches()
}

fn build_config(matches: &ArgMatches) -> Result<ScanConfig, String> {
    let target = matches.value_of("target").unwrap().to_string();
    
    // Parse port list or range
    let ports = if let Some(port_str) = matches.value_of("ports") {
        parse_port_list(port_str)?
    } else {
        Vec::new() // Empty Vec means all ports
    };
    
    // Parse number of threads
    let threads = matches.value_of("threads").unwrap()
        .parse::<usize>()
        .map_err(|_| "Invalid thread count".to_string())?;
    
    // Validate thread count
    if threads == 0 || threads > 1000 {
        return Err("Thread count must be between 1 and 1000".to_string());
    }
    
    // Parse timeout
    let timeout_ms = matches.value_of("timeout").unwrap()
        .parse::<u64>()
        .map_err(|_| "Invalid timeout value".to_string())?;
    
    // Validate timeout
    if timeout_ms < 100 || timeout_ms > 60000 {
        return Err("Timeout must be between 100ms and 60000ms".to_string());
    }
    
    // Parse output format
    let mut output_format = matches.value_of("format").unwrap().to_uppercase();
    if !["TEXT", "HTML", "JSON"].contains(&output_format.as_str()) {
        output_format = "TEXT".to_string();
    }
    
    // Create config
    let config = ScanConfig {
        target,
        ports,
        threads,
        timeout_ms,
        randomize_scan: matches.is_present("randomize"),
        verbose: matches.is_present("verbose"),
        offline_mode: matches.is_present("offline"),
        output_format,
        scan_offline_hosts: matches.is_present("scan-offline"),
        enhanced_vuln_detection: true,
        assess_attack_surface: true,
        check_misconfigurations: true,
        check_default_credentials: true,
        mitre_mapping: true,
        attack_path_analysis: true,
    };
    
    Ok(config)
}

/// Parse port specifications like "80,443" or "1-1000"
fn parse_port_list(port_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    
    for part in port_str.split(',') {
        if part.contains('-') {
            // Handle port range
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }
            
            let start = range_parts[0].parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", range_parts[0]))?;
            
            let end = range_parts[1].parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", range_parts[1]))?;
            
            if start > end {
                return Err(format!("Invalid port range: {}-{}", start, end));
            }
            
            for port in start..=end {
                ports.push(port);
            }
        } else {
            // Handle single port
            let port = part.parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", part))?;
            
            ports.push(port);
        }
    }
    
    // Remove duplicates
    ports.sort();
    ports.dedup();
    
    Ok(ports)
}

fn print_banner() {
    let banner = r#"
   _____           _   _   _      _   _____                 
  |  __ \         | | | \ | |    | | / ____|                
  | |__) |   _ ___| |_|  \| | ___| |_\____ __ __ _ _ __  
  |  _  / | | / __| __| . ` |/ _ \ __|  __) '__/ _` | '_ \ 
  | | \ \ |_| \__ \ |_| |\  |  __/ |_| | | | | (_| | | | |
  |_|  \_\__,_|___/\__|_| \_|\___|\__|_| |_|  \__,_|_| |_|
                                          
 "#;
    
    println!("{}", banner.bright_cyan());
    println!("{} {}", "Network Vulnerability Scanner".bright_cyan().bold(), format!("v{}", constants::VERSION).yellow());
    println!("{}\n", "-----------------------------------".bright_cyan());
}
