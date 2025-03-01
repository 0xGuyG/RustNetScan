// Author: CyberCraft Alchemist
// Utility functions for network scanning and service detection

use std::net::{IpAddr, TcpStream};
use std::time::Duration;
use std::io::{Read, Write};
use rand::{thread_rng, Rng, seq::SliceRandom};
use std::str::FromStr;

/// Check if a port is open by attempting a TCP connection
pub fn is_port_open(ip: &IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", ip, port);
    
    match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(timeout_ms)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Get the service banner from an open port
pub fn get_service_banner(ip: &IpAddr, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", ip, port);
    
    match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(timeout_ms)) {
        Ok(mut stream) => {
            // Set read timeout
            if stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).is_err() {
                return None;
            }
            
            // For HTTP ports, send a basic GET request
            if port == 80 || port == 443 || port == 8080 || port == 8443 {
                if stream.write_all(b"GET / HTTP/1.0\r\nHost: unknown\r\n\r\n").is_err() {
                    return None;
                }
            } else {
                // For other services, send a basic probe
                if stream.write_all(b"\r\n").is_err() {
                    return None;
                }
            }
            
            // Read the response
            let mut buffer = [0; 2048];
            match stream.read(&mut buffer) {
                Ok(size) => {
                    if size > 0 {
                        // Try to interpret as UTF-8, fall back to lossy conversion
                        match std::str::from_utf8(&buffer[..size]) {
                            Ok(s) => Some(s.trim().to_string()),
                            Err(_) => Some(String::from_utf8_lossy(&buffer[..size]).trim().to_string()),
                        }
                    } else {
                        None
                    }
                },
                Err(_) => None,
            }
        },
        Err(_) => None,
    }
}

/// Send a specific service probe to an open port
pub fn send_service_probe(ip: &IpAddr, port: u16, probe: &[u8], timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", ip, port);
    
    match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(timeout_ms)) {
        Ok(mut stream) => {
            // Set read timeout
            if stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).is_err() {
                return None;
            }
            
            // Send the probe
            if stream.write_all(probe).is_err() {
                return None;
            }
            
            // Read the response
            let mut buffer = [0; 4096];
            match stream.read(&mut buffer) {
                Ok(size) => {
                    if size > 0 {
                        // Try to interpret as UTF-8, fall back to lossy conversion
                        match std::str::from_utf8(&buffer[..size]) {
                            Ok(s) => Some(s.trim().to_string()),
                            Err(_) => Some(String::from_utf8_lossy(&buffer[..size]).trim().to_string()),
                        }
                    } else {
                        None
                    }
                },
                Err(_) => None,
            }
        },
        Err(_) => None,
    }
}

/// Identify service based on port number and banner
pub fn identify_service(port: u16, banner: &str) -> String {
    use crate::constants::COMMON_PORTS;
    
    // Check if there's a standard service for this port
    if let Some(service) = COMMON_PORTS.get(&port) {
        return service.to_string();
    }
    
    // Check for common service patterns in banner
    if banner.contains("SSH") || banner.contains("OpenSSH") {
        return "ssh".to_string();
    } else if banner.contains("HTTP") || banner.contains("http") {
        return "http".to_string();
    } else if banner.contains("FTP") {
        return "ftp".to_string();
    } else if banner.contains("SMTP") || banner.contains("Postfix") || banner.contains("mail") {
        return "smtp".to_string();
    } else if banner.contains("Telnet") {
        return "telnet".to_string();
    }
    
    // Default to "unknown"
    "unknown".to_string()
}

/// Check if a host is alive using ICMP ping
#[cfg(not(target_os = "windows"))]
pub fn ping_host(ip: &IpAddr) -> bool {
    use std::process::Command;
    
    let output = match ip {
        IpAddr::V4(_) => Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("1")
            .arg(ip.to_string())
            .output(),
        IpAddr::V6(_) => Command::new("ping6")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("1")
            .arg(ip.to_string())
            .output(),
    };
    
    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Check if a host is alive using ICMP ping (Windows)
#[cfg(target_os = "windows")]
pub fn ping_host(ip: &IpAddr) -> bool {
    use std::process::Command;
    
    let output = Command::new("ping")
        .arg("-n")
        .arg("1")
        .arg("-w")
        .arg("1000")
        .arg(ip.to_string())
        .output();
    
    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Check if a host is alive using TCP probing of common ports
pub fn tcp_ping_host(ip: &IpAddr, timeout_ms: u64) -> bool {
    // Check common ports that are likely to be open
    const COMMON_PORTS: [u16; 7] = [80, 443, 22, 445, 3389, 8080, 23];
    
    for port in &COMMON_PORTS {
        if is_port_open(ip, *port, timeout_ms) {
            return true;
        }
    }
    
    false
}

/// Randomize the order of ports to scan
pub fn randomize_ports(ports: &mut Vec<u16>) {
    let mut rng = thread_rng();
    ports.shuffle(&mut rng);
}

/// Randomize the order of hosts to scan
pub fn randomize_hosts(hosts: &mut Vec<IpAddr>) {
    let mut rng = thread_rng();
    hosts.shuffle(&mut rng);
}

/// Get a random port from a range
pub fn get_random_port(start: u16, end: u16) -> u16 {
    let mut rng = thread_rng();
    rng.gen_range(start..=end)
}

/// Get a random source port for a connection
pub fn get_random_source_port() -> u16 {
    let mut rng = thread_rng();
    rng.gen_range(10000..65000)
}

/// Find operating system from service banners
pub fn fingerprint_os(banners: &[String]) -> Option<String> {
    // Simple OS fingerprinting based on banner information
    let full_banner = banners.join(" ");
    let lower_banner = full_banner.to_lowercase();
    
    if lower_banner.contains("windows") {
        // Try to identify Windows version
        if lower_banner.contains("windows 10") || lower_banner.contains("windows server 2019") {
            return Some("Windows 10/Server 2019".to_string());
        } else if lower_banner.contains("windows server 2016") {
            return Some("Windows Server 2016".to_string());
        } else if lower_banner.contains("windows server 2012") {
            return Some("Windows Server 2012".to_string());
        } else if lower_banner.contains("windows 7") || lower_banner.contains("windows server 2008") {
            return Some("Windows 7/Server 2008".to_string());
        } else {
            return Some("Windows".to_string());
        }
    } else if lower_banner.contains("ubuntu") {
        return Some("Ubuntu Linux".to_string());
    } else if lower_banner.contains("debian") {
        return Some("Debian Linux".to_string());
    } else if lower_banner.contains("centos") {
        return Some("CentOS Linux".to_string());
    } else if lower_banner.contains("red hat") || lower_banner.contains("rhel") {
        return Some("Red Hat Linux".to_string());
    } else if lower_banner.contains("fedora") {
        return Some("Fedora Linux".to_string());
    } else if lower_banner.contains("linux") {
        return Some("Linux".to_string());
    } else if lower_banner.contains("freebsd") {
        return Some("FreeBSD".to_string());
    } else if lower_banner.contains("openbsd") {
        return Some("OpenBSD".to_string());
    } else if lower_banner.contains("macos") || lower_banner.contains("mac os") {
        return Some("macOS".to_string());
    }
    
    None
}

/// Generate a random MAC address for spoofing
pub fn generate_random_mac() -> String {
    let mut rng = thread_rng();
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        // First byte, ensure it's unicast and locally administered
        rng.gen::<u8>() & 0xFE | 0x02,
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>()
    )
}

/// Generate a random IPv4 address
pub fn generate_random_ipv4() -> IpAddr {
    let mut rng = thread_rng();
    let a = rng.gen::<u8>();
    let b = rng.gen::<u8>();
    let c = rng.gen::<u8>();
    let d = rng.gen::<u8>();
    
    // Avoid private IP ranges
    if (a == 10) || 
       (a == 172 && b >= 16 && b <= 31) || 
       (a == 192 && b == 168) || 
       (a == 127) || 
       (a == 0) || 
       (a >= 224) {
        return generate_random_ipv4();
    }
    
    IpAddr::from_str(&format!("{}.{}.{}.{}", a, b, c, d)).unwrap()
}

/// Format an IP range for display
pub fn format_ip_range(start: &IpAddr, end: &IpAddr) -> String {
    if let (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) = (start, end) {
        format!("{}-{}", start_v4, end_v4)
    } else {
        format!("{}..{}", start, end)
    }
}
