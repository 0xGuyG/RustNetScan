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

# 2. Build for Windows (using GNU toolchain)
echo "=== Building for Windows (GNU toolchain) ==="
WINDOWS_EXE="$OUTPUT_DIR/rustnet_scan-windows.exe"
WINDOWS_BUILD_SUCCESS=0

# Check if we already have a Windows executable from previous builds
if [ -f "$WINDOWS_EXE" ]; then
    EXISTING_WIN_EXE_TIME=$(stat -f "%m" "$WINDOWS_EXE")
    echo "Found existing Windows executable (last modified: $(date -r $EXISTING_WIN_EXE_TIME))"
fi

# Check if mingw32 is installed
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "\033[33m⚠️ MinGW toolchain (x86_64-w64-mingw32-gcc) not found. You can install it with 'brew install mingw-w64'\033[0m"
    if [ -f "$WINDOWS_EXE" ]; then
        echo "\033[33m⚠️ Using existing Windows executable from previous successful build\033[0m"
        echo "   Path: $WINDOWS_EXE"
        echo "   Date: $(date -r $EXISTING_WIN_EXE_TIME)"
        WINDOWS_BUILD_SUCCESS=1
    fi
else
    # Attempt to build for Windows with GNU toolchain
    cargo build --release --target x86_64-pc-windows-gnu
    if [ $? -eq 0 ]; then
        cp "$BUILD_DIR/../x86_64-pc-windows-gnu/release/rustnet_scan.exe" "$WINDOWS_EXE"
        echo "✅ Windows build successful: $WINDOWS_EXE"
        WINDOWS_BUILD_SUCCESS=1
    else
        echo "❌ Windows build failed with GNU toolchain"
        
        # If cross-compilation failed but we have an existing executable, keep it
        if [ -f "$WINDOWS_EXE" ]; then
            echo "\033[33m⚠️ Using existing Windows executable from previous successful build\033[0m"
            echo "   Path: $WINDOWS_EXE"
            echo "   Date: $(date -r $EXISTING_WIN_EXE_TIME)"
            WINDOWS_BUILD_SUCCESS=1
        fi
    fi
fi

# Only if Windows build completely failed (no existing executable either)
if [ $WINDOWS_BUILD_SUCCESS -eq 0 ]; then
    echo "\033[33m⚠️ No Windows executable available. Build will need to be performed on Windows.\033[0m"
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
