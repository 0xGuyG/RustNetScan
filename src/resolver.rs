// Author: CyberCraft Alchemist
// Hostname resolution and network target expansion functionalities

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::error::ResolveError;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

/// Resolves a hostname or IP range to a list of IP addresses
pub fn resolve_targets(target_spec: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    
    // Check if the target is a CIDR notation (e.g., 192.168.1.0/24)
    if target_spec.contains('/') {
        if let Some(cidr_ips) = expand_cidr(target_spec) {
            ips.extend(cidr_ips);
            return ips;
        }
    }
    
    // Check if the target is an IP range (e.g., 192.168.1.1-192.168.1.254)
    if target_spec.contains('-') {
        if let Some(range_ips) = expand_ip_range(target_spec) {
            ips.extend(range_ips);
            return ips;
        }
    }
    
    // Try to parse as an IP address first
    if let Ok(ip) = IpAddr::from_str(target_spec) {
        ips.push(ip);
        return ips;
    }
    
    // Otherwise, try DNS resolution
    match resolve_hostname(target_spec) {
        Ok(resolved_ips) => {
            if !resolved_ips.is_empty() {
                ips.extend(resolved_ips);
            }
        },
        Err(_) => {
            // If regular DNS resolution fails, try additional methods
            if let Some(hostname) = target_spec.to_socket_addrs().ok().and_then(|mut addrs| {
                addrs.next().map(|socket_addr| socket_addr.ip())
            }) {
                ips.push(hostname);
            }
        }
    }
    
    ips
}

/// Resolves a hostname to IP addresses using DNS
pub fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>, ResolveError> {
    // Configure DNS resolver with reasonable timeouts
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    
    let resolver = Resolver::new(ResolverConfig::default(), opts)?;
    
    let response = resolver.lookup_ip(hostname)?;
    let ips: Vec<IpAddr> = response.iter().collect();
    
    Ok(ips)
}

/// Perform a reverse DNS lookup to get a hostname from an IP
pub fn reverse_lookup(ip: &IpAddr) -> Option<String> {
    // Configure DNS resolver with reasonable timeouts
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;
    
    if let Ok(resolver) = Resolver::new(ResolverConfig::default(), opts) {
        if let Ok(response) = resolver.reverse_lookup(*ip) {
            if let Some(name) = response.iter().next() {
                return Some(name.to_utf8());
            }
        }
    }
    
    None
}

/// Get NetBIOS name for an IP (Windows)
#[cfg(target_os = "windows")]
pub fn get_netbios_name(ip: &IpAddr) -> Option<String> {
    use std::process::Command;
    
    let output = Command::new("nbtstat")
        .arg("-A")
        .arg(ip.to_string())
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse nbtstat output to extract the NetBIOS name
    for line in stdout.lines() {
        if line.contains("<00>") && line.contains("UNIQUE") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                return Some(parts[0].trim().to_string());
            }
        }
    }
    
    None
}

/// Get NetBIOS name for an IP (Unix-like systems)
#[cfg(not(target_os = "windows"))]
pub fn get_netbios_name(ip: &IpAddr) -> Option<String> {
    use std::process::Command;
    
    // Try using nmblookup if available (part of Samba)
    let output = Command::new("nmblookup")
        .arg("-A")
        .arg(ip.to_string())
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse nmblookup output
    for line in stdout.lines() {
        if line.contains("<00>") {
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.len() > 0 {
                return Some(parts[0].trim().to_string());
            }
        }
    }
    
    None
}

/// Get the local hostname of the system
pub fn get_local_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| {
            let output = std::process::Command::new("hostname")
                .output()
                .map_err(|e| e.to_string())?;
            
            String::from_utf8(output.stdout)
                .map(|s| s.trim().to_string())
                .map_err(|_| "Failed to parse hostname output".to_string())
        })
        .ok()
}

/// Get the local DNS domain
#[cfg(target_os = "windows")]
pub fn get_local_domain() -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(tcp_ip) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters") {
        if let Ok(domain) = tcp_ip.get_value::<String, _>("Domain") {
            if !domain.is_empty() {
                return Some(domain);
            }
        }
    }
    None
}

/// Get the local DNS domain on Unix-like systems
#[cfg(not(target_os = "windows"))]
pub fn get_local_domain() -> Option<String> {
    // Try reading from /etc/resolv.conf
    if let Ok(resolv_conf) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in resolv_conf.lines() {
            if line.starts_with("domain ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return Some(parts[1].to_string());
                }
            }
        }
    }
    
    // Alternatively, try the 'dnsdomainname' command
    let output = std::process::Command::new("dnsdomainname")
        .output()
        .ok()?;
    
    let domain = String::from_utf8(output.stdout).ok()?;
    let domain = domain.trim();
    
    if !domain.is_empty() {
        return Some(domain.to_string());
    }
    
    None
}

/// Expand a CIDR notation into individual IP addresses
pub fn expand_cidr(cidr: &str) -> Option<Vec<IpAddr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let ip_str = parts[0];
    let prefix_len = parts[1].parse::<u8>().ok()?;
    
    // Only support IPv4 CIDR for now
    let ip = Ipv4Addr::from_str(ip_str).ok()?;
    
    if prefix_len > 32 {
        return None;
    }
    
    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    
    let network = ip_u32 & mask;
    let broadcast = network | !mask;
    
    let mut ips = Vec::new();
    
    // Skip network and broadcast addresses if prefix_len <= 30
    let start = if prefix_len <= 30 { network + 1 } else { network };
    let end = if prefix_len <= 30 { broadcast - 1 } else { broadcast };
    
    for i in start..=end {
        let ip = Ipv4Addr::from(i);
        ips.push(IpAddr::V4(ip));
    }
    
    Some(ips)
}

/// Expand an IP range into individual IP addresses
pub fn expand_ip_range(range: &str) -> Option<Vec<IpAddr>> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let start_ip = Ipv4Addr::from_str(parts[0]).ok()?;
    let end_ip = Ipv4Addr::from_str(parts[1]).ok()?;
    
    let start_u32 = u32::from(start_ip);
    let end_u32 = u32::from(end_ip);
    
    if end_u32 < start_u32 {
        return None;
    }
    
    // Limit range to avoid excessive memory usage
    if end_u32 - start_u32 > 65535 {
        return None;
    }
    
    let mut ips = Vec::new();
    for i in start_u32..=end_u32 {
        let ip = Ipv4Addr::from(i);
        ips.push(IpAddr::V4(ip));
    }
    
    Some(ips)
}

/// Comprehensive hostname resolution that tries multiple methods
pub fn resolve_hostname_comprehensive(ip: &IpAddr) -> String {
    // First try reverse DNS
    if let Some(hostname) = reverse_lookup(ip) {
        return hostname;
    }
    
    // Then try NetBIOS name
    if let Some(netbios_name) = get_netbios_name(ip) {
        return netbios_name;
    }
    
    // Fall back to IP address string
    ip.to_string()
}
