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

// MITRE ATT&CK Framework Mappings
lazy_static::lazy_static! {
    pub static ref MITRE_ATTACK_MAPPINGS: HashMap<String, Vec<String>> = {
        let mut m: HashMap<String, Vec<String>> = HashMap::new();
        
        // CWE to MITRE ATT&CK Technique mappings
        m.insert("CWE-78".to_string(), vec!["T1059".to_string()]); // OS Command Injection
        m.insert("CWE-79".to_string(), vec!["T1059.007".to_string()]); // XSS
        m.insert("CWE-89".to_string(), vec!["T1190".to_string()]); // SQL Injection
        m.insert("CWE-94".to_string(), vec!["T1059.007".to_string()]); // Code Injection
        m.insert("CWE-22".to_string(), vec!["T1083".to_string()]); // Path Traversal
        m.insert("CWE-250".to_string(), vec!["T1068".to_string()]); // Privilege Elevation
        m.insert("CWE-306".to_string(), vec!["T1078".to_string()]); // Authentication Issues
        m.insert("CWE-502".to_string(), vec!["T1195".to_string()]); // Deserialization
        m.insert("CWE-269".to_string(), vec!["T1068".to_string()]); // Improper Privilege Management
        m.insert("CWE-287".to_string(), vec!["T1110".to_string()]); // Authentication Issues
        
        m
    };
}

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
        
        // Additional common web vulnerabilities
        v.push((
            "http", 
            Regex::new(r"(?i)IIS/[5-7]\.").unwrap(),
            "CVE-2015-1635".to_string(),
            "Microsoft IIS HTTP.sys Remote Code Execution vulnerability".to_string()
        ));
        
        v.push((
            "http",
            Regex::new(r"(?i)apache/2\.4\.[0-2][0-9]").unwrap(),
            "CVE-2021-41773".to_string(),
            "Apache HTTP Server 2.4.49/2.4.50 Path Traversal vulnerability".to_string()
        ));
        
        v.push((
            "mysql",
            Regex::new(r"(?i)mysql.*5\.[0-6]\.").unwrap(),
            "CVE-2016-6662".to_string(),
            "MySQL Remote Code Execution vulnerability in versions 5.5.x and 5.6.x".to_string()
        ));
        
        // Cloud services vulnerabilities
        v.push((
            "aws",
            Regex::new(r"(?i)aws.*lambda").unwrap(),
            "CLOUD-LAMBDA-MISCONFIG".to_string(),
            "Potential AWS Lambda misconfiguration exposing sensitive functionality".to_string()
        ));

        v.push((
            "azure",
            Regex::new(r"(?i)azure.*storage").unwrap(),
            "CLOUD-AZURE-STORAGE-PUBLIC".to_string(),
            "Publicly accessible Azure Storage detected, check for data exposure".to_string()
        ));
        
        // Container vulnerabilities
        v.push((
            "docker",
            Regex::new(r"(?i)Docker/[0-1][0-8]").unwrap(),
            "CONTAINER-DOCKER-OLD".to_string(),
            "Outdated Docker version with known security vulnerabilities".to_string()
        ));
        
        v.push((
            "kubernetes",
            Regex::new(r"(?i)k8s.*v1\.(1[0-8]|[0-9])\.").unwrap(),
            "CONTAINER-K8S-OLD".to_string(),
            "Outdated Kubernetes version with known security vulnerabilities".to_string()
        ));
        
        // IoT vulnerabilities
        v.push((
            "iot",
            Regex::new(r"(?i)(camera|dvr|nvr|hikvision|dahua)").unwrap(),
            "IOT-CAMERA-DEFAULT-CREDS".to_string(),
            "IoT camera systems often have default or weak credentials, check authentication".to_string()
        ));
        
        v.push((
            "upnp",
            Regex::new(r"(?i)upnp/1\.").unwrap(),
            "IOT-UPNP-EXPOSURE".to_string(),
            "UPnP service exposed, potential for device discovery and unauthorized access".to_string()
        ));
        
        // Additional OT/ICS vulnerabilities
        v.push((
            "dnp3",
            Regex::new(r"(?i)dnp3").unwrap(),
            "OT-DNP3-NOAUTH".to_string(),
            "DNP3 protocol lacks robust authentication mechanisms, allowing unauthorized control".to_string()
        ));
        
        v.push((
            "plc",
            Regex::new(r"(?i)(plc|programmable.*controller)").unwrap(),
            "OT-PLC-EXPOSURE".to_string(),
            "PLC systems should not be directly exposed to networks, potential control system compromise".to_string()
        ));
        
        // Critical services that shouldn't be exposed
        v.push((
            "database",
            Regex::new(r"(?i)(mysql|postgresql|mongodb|redis|cassandra)").unwrap(),
            "EXPOSED-DATABASE".to_string(),
            "Database services directly exposed to network, potential data breach risk".to_string()
        ));
        
        v.push((
            "admin",
            Regex::new(r"(?i)(admin|management|manager|config)").unwrap(),
            "EXPOSED-ADMIN".to_string(),
            "Administrative interface potentially exposed, check access controls".to_string()
        ));
        
        v
    };

    // Common security misconfigurations to check
    pub static ref SECURITY_MISCONFIGURATIONS: Vec<(&'static str, Regex, String, String, String)> = {
        let mut m = Vec::new();
        
        // Format: (service_name, regex_pattern, misconfig_id, description, recommendation)
        
        // HTTP service misconfigurations
        m.push((
            "http", 
            Regex::new(r"(?i)Server:.*").unwrap(),
            "MISCONFIG-HTTP-SERVER-DISCLOSURE".to_string(),
            "Web server revealing detailed version information".to_string(),
            "Configure the server to hide detailed version information in headers".to_string()
        ));
        
        m.push((
            "http", 
            Regex::new(r"(?i)X-Powered-By:.*").unwrap(),
            "MISCONFIG-HTTP-TECH-DISCLOSURE".to_string(),
            "Web application revealing technology stack information".to_string(),
            "Configure the application to hide technology information in headers".to_string()
        ));
        
        // SSL/TLS misconfigurations
        m.push((
            "ssl", 
            Regex::new(r"(?i)SSLv3|TLSv1\.0|TLSv1\.1").unwrap(),
            "MISCONFIG-SSL-OLD-PROTOCOL".to_string(),
            "Server supporting outdated SSL/TLS protocols".to_string(),
            "Disable outdated protocols (SSLv3, TLSv1.0, TLSv1.1) and enable only TLSv1.2 and above".to_string()
        ));
        
        // SSH misconfigurations
        m.push((
            "ssh", 
            Regex::new(r"(?i)(password|keyboard).*authentication").unwrap(),
            "MISCONFIG-SSH-PASSWORD-AUTH".to_string(),
            "SSH server allowing password authentication".to_string(),
            "Configure SSH to use key-based authentication only and disable password authentication".to_string()
        ));
        
        // DNS misconfigurations
        m.push((
            "dns", 
            Regex::new(r"(?i)AXFR").unwrap(),
            "MISCONFIG-DNS-ZONE-TRANSFER".to_string(),
            "DNS server allowing zone transfers".to_string(),
            "Configure DNS server to restrict zone transfers to authorized servers only".to_string()
        ));
        
        // SNMP misconfigurations
        m.push((
            "snmp", 
            Regex::new(r"(?i)public|private").unwrap(),
            "MISCONFIG-SNMP-DEFAULT-COMMUNITY".to_string(),
            "SNMP server using default community strings".to_string(),
            "Change default SNMP community strings and restrict access to authorized hosts".to_string()
        ));
        
        m
    };

    // Default credentials to check
    pub static ref DEFAULT_CREDENTIALS: Vec<(&'static str, u16, &'static str, &'static str)> = {
        let mut c = Vec::new();
        
        // Format: (service_name, default_port, username, password)
        c.push(("ssh", 22, "admin", "admin"));
        c.push(("ssh", 22, "root", "root"));
        c.push(("ssh", 22, "user", "password"));
        
        c.push(("ftp", 21, "anonymous", ""));
        c.push(("ftp", 21, "admin", "admin"));
        c.push(("ftp", 21, "ftp", "ftp"));
        
        c.push(("telnet", 23, "admin", "admin"));
        c.push(("telnet", 23, "root", "root"));
        c.push(("telnet", 23, "user", "password"));
        
        c.push(("http", 80, "admin", "admin"));
        c.push(("http", 80, "administrator", "password"));
        
        c.push(("http", 8080, "admin", "admin"));
        c.push(("http", 8080, "tomcat", "tomcat"));
        
        c.push(("http", 8443, "admin", "admin"));
        c.push(("http", 8443, "admin", "password"));
        
        c.push(("snmp", 161, "public", ""));
        c.push(("snmp", 161, "private", ""));
        
        c.push(("mysql", 3306, "root", ""));
        c.push(("mysql", 3306, "root", "password"));
        c.push(("mysql", 3306, "root", "root"));
        
        c.push(("postgres", 5432, "postgres", "postgres"));
        c.push(("postgres", 5432, "postgres", "password"));
        
        // OT/ICS specific
        c.push(("modbus", 502, "admin", "admin"));
        c.push(("bacnet", 47808, "admin", "admin"));
        c.push(("ethernet/ip", 44818, "admin", "1234"));
        
        c
    };
}
