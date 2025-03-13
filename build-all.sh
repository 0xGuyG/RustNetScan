#!/bin/bash
# Script to build RustNetScan for multiple platforms

# Set directories
BUILD_DIR="./target/release"
OUTPUT_DIR="./dist"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "Building RustNetScan for multiple platforms..."

# 1. Build for macOS (native)
echo "=== Building for macOS ==="
cargo build --release
if [ $? -eq 0 ]; then
    cp "$BUILD_DIR/rustnet_scan" "$OUTPUT_DIR/rustnet_scan-macos"
    echo "✅ macOS build successful: $OUTPUT_DIR/rustnet_scan-macos"
else
    echo "❌ macOS build failed"
fi

# 2. Build for Windows
echo "=== Building for Windows ==="
cargo build --release --target x86_64-pc-windows-msvc
if [ $? -eq 0 ]; then
    cp "$BUILD_DIR/../x86_64-pc-windows-msvc/release/rustnet_scan.exe" "$OUTPUT_DIR/rustnet_scan-windows.exe"
    echo "✅ Windows build successful: $OUTPUT_DIR/rustnet_scan-windows.exe"
else
    echo "❌ Windows build failed"
fi

# 3. Build for Linux (compatible with Kali Linux)
echo "=== Building for Linux (compatible with Kali) ==="
cargo build --release --target x86_64-unknown-linux-gnu
if [ $? -eq 0 ]; then
    cp "$BUILD_DIR/../x86_64-unknown-linux-gnu/release/rustnet_scan" "$OUTPUT_DIR/rustnet_scan-linux"
    echo "✅ Linux build successful: $OUTPUT_DIR/rustnet_scan-linux"
else
    echo "❌ Linux build failed"
fi

echo "Build process completed. Check $OUTPUT_DIR directory for output binaries."
