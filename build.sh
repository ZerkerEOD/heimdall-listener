#!/bin/bash

# Exit on error
set -e

# Check for required tools
if ! command -v fyne &> /dev/null; then
    echo "fyne CLI is not installed. Installing..."
    go install fyne.io/fyne/v2/cmd/fyne@latest
fi

# Clean up any previous builds
rm -rf build fyne-cross heimdall-listener heimdall-listener.tar.xz usr Makefile cmd/heimdall-listener/*.exe

# Create a build directory if it doesn't exist
mkdir -p build

# Build for Windows 64-bit
echo "Building for Windows 64-bit..."
if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # On Linux/MacOS, use fyne package with proper flags
    GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc fyne package -os windows -appID com.heimdall.listener -release -sourceDir ./cmd/heimdall-listener
    mv cmd/heimdall-listener/*.exe build/heimdall-listener-windows-amd64.exe
else
    # On Windows, use fyne-cross
    fyne-cross windows -arch=amd64 -app-id com.heimdall.listener -release ./cmd/heimdall-listener
    mv fyne-cross/bin/windows-amd64/* build/
fi

# Build for Linux 64-bit
echo "Building for Linux 64-bit..."
fyne package -os linux -appID com.heimdall.listener -release -sourceDir ./cmd/heimdall-listener

# Extract Linux tar.xz and move executable
if [ -f "heimdall-listener.tar.xz" ]; then
    tar -xf heimdall-listener.tar.xz
    if [ -f "usr/local/bin/heimdall-listener" ]; then
        mv usr/local/bin/heimdall-listener build/heimdall-listener-linux-amd64
    elif [ -f "cmd/heimdall-listener/heimdall-listener" ]; then
        mv cmd/heimdall-listener/heimdall-listener build/heimdall-listener-linux-amd64
    elif [ -f "heimdall-listener" ]; then
        mv heimdall-listener build/heimdall-listener-linux-amd64
    else
        echo "Error: Could not find Linux executable after extraction"
        exit 1
    fi
else
    echo "Error: Could not find heimdall-listener.tar.xz"
    exit 1
fi

# Cleanup temporary files and directories
rm -rf fyne-cross heimdall-listener heimdall-listener.tar.xz usr Makefile cmd/heimdall-listener/*.exe

echo "Build complete. Executables are in the 'build' directory."
