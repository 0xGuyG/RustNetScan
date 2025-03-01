// Author: CyberCraft Alchemist
// Constants and definitions for the network vulnerability scanner

use std::collections::HashMap;
use regex::Regex;

// Define the version and name of our tool
pub const VERSION: &str = "1.0.0";
pub const TOOL_NAME: &str = "Rust Network Vulnerability Scanner";

// Define timeout durations
pub const PING_TIMEOUT_MS: u64 = 1000;
pub const PORT_SCAN_TIMEOUT_MS: u64 = 2000;
pub const BANNER_GRAB_TIMEOUT_MS: u64 = 3000;

// Define service probing templates
lazy_static::lazy_static! {
    pub static ref SERVICE_PROBES: HashMap<u16, Vec<u8>> = {
        let mut m: HashMap<u16, Vec<u8>> = HashMap::new();
        m.insert(21, b"USER anonymous\r\n".to_vec());
        m.insert(22, b"SSH-2.0-Rust-Scanner\r\n".to_vec());
        m.insert(23, b"\r\n".to_vec());
        m.insert(25, b"EHLO rust-scanner.local\r\n".to_vec());
        m.insert(80, b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Rust-Scanner/1.0\r\nConnection: close\r\n\r\n".to_vec());
        m.insert(443, b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Rust-Scanner/1.0\r\nConnection: close\r\n\r\n".to_vec());
        m.insert(110, b"USER anonymous\r\n".to_vec());
        m.insert(143, b"A001 CAPABILITY\r\n".to_vec());
        m.insert(587, b"EHLO rust-scanner.local\r\n".to_vec());
        m.insert(3389, b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec());
        m.insert(5060, b"OPTIONS sip:localhost SIP/2.0\r\nVia: SIP/2.0/UDP rust-scanner:5060\r\nMax-Forwards: 70\r\nFrom: <sip:scanner@rust-scanner>\r\nTo: <sip:scanner@rust-scanner>\r\nCall-ID: scan123\r\nCSeq: 1 OPTIONS\r\nContact: <sip:scanner@rust-scanner>\r\nAccept: application/sdp\r\nContent-Length: 0\r\n\r\n".to_vec());
        m.insert(8080, b"GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: Rust-Scanner/1.0\r\nConnection: close\r\n\r\n".to_vec());
        m.insert(9100, b"\x1B%-12345X@PJL INFO STATUS\r\n\x1B%-12345X\r\n".to_vec());
        
        // OT protocol probes
        m.insert(44818, b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()); // EtherNet/IP
        m.insert(47808, b"\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08".to_vec()); // BACnet
        m.insert(502, b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A".to_vec()); // Modbus
        m.insert(20000, b"\x05\x64\x1a\x00\x00\x04\x00\x00\x00\x00\x00\x00\x04\x01\x00\x00\x01".to_vec()); // DNP3
        m.insert(4840, b"GET / HTTP/1.1\r\nHost: localhost:4840\r\nUser-Agent: Rust-Scanner/1.0\r\nConnection: close\r\n\r\n".to_vec()); // OPC UA HTTP
        
        m
    };

    // OT protocol definitions
    pub static ref OT_PROTOCOLS: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(102, "ISO-TSAP (Siemens S7)");
        m.insert(502, "Modbus TCP");
        m.insert(1089, "FF Fieldbus Message Specification");
        m.insert(1090, "FF Fieldbus Message Specification");
        m.insert(1091, "FF Fieldbus Message Specification");
        m.insert(1541, "Foxboro/Invensys Foxapi");
        m.insert(2222, "EtherNet/IP");
        m.insert(4840, "OPC UA");
        m.insert(9600, "OMRON FINS");
        m.insert(10000, "Codesys Runtime");
        m.insert(18245, "GE SRTP");
        m.insert(18246, "GE SRTP");
        m.insert(20000, "DNP3");
        m.insert(34962, "PROFInet RT");
        m.insert(34963, "PROFInet RT");
        m.insert(34964, "PROFInet RT");
        m.insert(34980, "EtherCAT");
        m.insert(44818, "EtherNet/IP");
        m.insert(45678, "Schneider");
        m.insert(47808, "BACnet");
        m.insert(55000, "FL-net");
        m.insert(55003, "FL-net");
        m
    };

    // Common ports - significantly expanded
    pub static ref COMMON_PORTS: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        // Standard services
        m.insert(21, "FTP");
        m.insert(22, "SSH");
        m.insert(23, "Telnet");
        m.insert(25, "SMTP");
        m.insert(53, "DNS");
        m.insert(80, "HTTP");
        m.insert(88, "Kerberos");
        m.insert(110, "POP3");
        m.insert(111, "RPC");
        m.insert(119, "NNTP");
        m.insert(123, "NTP");
        m.insert(135, "MS-RPC");
        m.insert(137, "NetBIOS-NS");
        m.insert(138, "NetBIOS-DGM");
        m.insert(139, "NetBIOS-SSN");
        m.insert(143, "IMAP");
        m.insert(161, "SNMP");
        m.insert(162, "SNMP-Trap");
        m.insert(389, "LDAP");
        m.insert(443, "HTTPS");
        m.insert(445, "Microsoft-DS");
        m.insert(464, "Kerberos");
        m.insert(465, "SMTPS");
        m.insert(500, "IKE/ISAKMP");
        m.insert(514, "SysLog");
        m.insert(587, "SMTP Submission");
        m.insert(636, "LDAPS");
        m.insert(993, "IMAPS");
        m.insert(995, "POP3S");
        m.insert(1080, "SOCKS");
        m.insert(1433, "MS SQL");
        m.insert(1434, "MS SQL Browser");
        m.insert(1521, "Oracle DB");
        m.insert(1723, "PPTP");
        m.insert(3306, "MySQL");
        m.insert(3389, "RDP");
        m.insert(5432, "PostgreSQL");
        m.insert(5900, "VNC");
        m.insert(5901, "VNC-1");
        m.insert(5902, "VNC-2");
        m.insert(5903, "VNC-3");
        m.insert(8080, "HTTP-Proxy");
        m.insert(8443, "HTTPS-Alt");
        
        // Add OT protocol ports
        for (&port, &service) in OT_PROTOCOLS.iter() {
            m.insert(port, service);
        }
        
        m
    };

    // Common vulnerability patterns
    pub static ref VULNERABILITY_PATTERNS: Vec<(&'static str, Regex, String, String)> = {
        let mut v = Vec::new();

        // Format: (service_name, regex_pattern, vulnerability_id, vulnerability_description)
        v.push((
            "ssh", 
            Regex::new(r"(?i)OpenSSH_[1-6]\.").unwrap(),
            "CVE-2020-14145".to_string(),
            "Potential OpenSSH vulnerability in older versions that may leak data or allow MITM attacks".to_string()
        ));
        
        v.push((
            "apache", 
            Regex::new(r"(?i)apache/2\.[0-3]\.").unwrap(),
            "CVE-2017-9798".to_string(),
            "Apache HTTP Server 2.2.x through 2.3.x vulnerable to Optionsbleed attack".to_string()
        ));
        
        v.push((
            "nginx", 
            Regex::new(r"(?i)nginx/1\.[0-9]\.").unwrap(),
            "CVE-2019-9511".to_string(),
            "HTTP/2 large amount of data request leads to DOS".to_string()
        ));
        
        v.push((
            "ftp", 
            Regex::new(r"(?i)vsftpd 2\.").unwrap(),
            "CVE-2011-2523".to_string(),
            "VSFTPD 2.3.4 and older vulnerable to backdoor command execution".to_string()
        ));
        
        v.push((
            "telnet", 
            Regex::new(r"(?i)telnet").unwrap(),
            "TELNET-CLEARTEXT".to_string(),
            "Telnet transmits all data in cleartext, risking exposure of credentials".to_string()
        ));
        
        v.push((
            "rdp", 
            Regex::new(r"(?i)windows.*terminal").unwrap(),
            "CVE-2019-0708".to_string(),
            "BlueKeep: Remote desktop vulnerability may allow remote code execution".to_string()
        ));
        
        // OT-specific vulnerabilities
        v.push((
            "modbus", 
            Regex::new(r"(?i)modbus").unwrap(),
            "OT-MODBUS-NOAUTH".to_string(),
            "Modbus protocol lacks authentication mechanisms, allowing unauthorized control".to_string()
        ));
        
        v.push((
            "siemens", 
            Regex::new(r"(?i)S7").unwrap(),
            "OT-S7-CLEARTEXT".to_string(),
            "Siemens S7 communication protocols transmit data in cleartext".to_string()
        ));
        
        v.push((
            "bacnet", 
            Regex::new(r"(?i)bacnet").unwrap(),
            "OT-BACNET-NOAUTH".to_string(),
            "BACnet protocol lacks robust authentication, allowing unauthorized access to building controls".to_string()
        ));
        
        v.push((
            "ethernet/ip", 
            Regex::new(r"(?i)ethernet/ip").unwrap(),
            "OT-EIP-NOAUTH".to_string(),
            "EtherNet/IP protocol has limited security controls for authentication and authorization".to_string()
        ));
        
        v
    };
}
