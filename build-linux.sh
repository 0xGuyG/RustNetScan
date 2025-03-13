#!/bin/bash
# Script to build RustNetScan for Linux systems (including Kali Linux)
# This script should be run on a Linux system

# Make sure Rust is installed
command -v cargo >/dev/null 2>&1 || { 
    echo "Rust is not installed. Please install Rust first with:" 
    echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
}

# Install OpenSSL dev packages
if command -v apt-get >/dev/null 2>&1; then
    echo "Debian/Ubuntu/Kali based system detected"
    sudo apt-get update
    sudo apt-get install -y pkg-config libssl-dev
elif command -v dnf >/dev/null 2>&1; then
    echo "Fedora/RHEL based system detected"
    sudo dnf install -y openssl-devel
elif command -v pacman >/dev/null 2>&1; then
    echo "Arch based system detected"
    sudo pacman -S --noconfirm openssl
else
    echo "Could not detect package manager. Please install OpenSSL development packages manually."
fi

# Build RustNetScan
echo "Building RustNetScan for Linux..."
cargo build --release

# Create output directory
mkdir -p ./dist

# Copy the binary to the dist directory
cp ./target/release/rustnet_scan ./dist/rustnet_scan-linux

echo "Linux build complete: ./dist/rustnet_scan-linux"
echo "To make the binary executable, run: chmod +x ./dist/rustnet_scan-linux"
