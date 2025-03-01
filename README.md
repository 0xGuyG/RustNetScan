# RustNet Scan

A comprehensive, high-performance network vulnerability scanner written in Rust.

## Features

- **Network Scanning**
  - ICMP ping sweeps
  - Port scanning (all 65,535 ports supported)
  - Service and banner detection
  - Vulnerability identification
  - Randomized scanning option
  - Multi-threaded scanning using Rayon

- **Hostname Resolution**
  - DNS reverse lookup
  - NetBIOS name resolution
  - Local hostname lookups
  - Multiple resolution methods

- **Vulnerability Detection**
  - CVE database integration
  - NVD and CIRCL CVE API queries
  - Offline vulnerability pattern matching
  - OT (Operational Technology) protocol support

- **Reporting**
  - Multiple output formats:
    - Text
    - HTML
    - JSON
  - Detailed vulnerability information
  - Color-coded severity indicators

## Installation

### Prerequisites

- Rust 1.58.0 or later
- Cargo package manager

### Building from Source

```bash
git clone https://github.com/yourusername/RustNetScan.git
cd RustNetScan
cargo build --release
```

The compiled binary will be available at `target/release/rustnet_scan`.

## Usage

Basic usage:

```bash
./rustnet_scan 192.168.1.0/24
```

Scan specific ports:

```bash
./rustnet_scan -p 22,80,443 192.168.1.1
```

Scan with randomization and increased threads:

```bash
./rustnet_scan -r -t 100 192.168.1.0/24
```

Generate an HTML report:

```bash
./rustnet_scan -f HTML 192.168.1.0/24
```

### Command Line Options

- `target`: Target specification (IP, range, CIDR, or hostname)
- `-p, --ports`: Ports to scan (e.g., '22,80,443' or '1-1000')
- `-t, --threads`: Number of concurrent threads (default: 50)
- `-w, --timeout`: Connection timeout in milliseconds (default: 1000)
- `-r, --randomize`: Randomize scan order
- `-f, --format`: Output format (TEXT, HTML, JSON) (default: TEXT)
- `-v, --verbose`: Verbose output
- `--offline`: Offline mode - don't query online CVE databases

## Security Considerations

This tool is designed for legitimate security testing only. Please ensure you have permission to scan the target network.

- No credential storage
- No exploitation capabilities
- Configurable scan rates
- Randomization to avoid detection
- Offline mode support
- Minimal information exposure

