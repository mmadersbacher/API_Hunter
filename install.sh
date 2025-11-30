#!/bin/bash
# API Hunter Installation Script for Linux (Kali, Ubuntu, Debian, etc.)

set -e

echo "======================================================================"
echo "                 API Hunter Installation Script"
echo "======================================================================"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "[!] Please do not run as root. Run as normal user with sudo privileges."
    exit 1
fi

# Check for Rust installation
if ! command -v cargo &> /dev/null; then
    echo "[*] Rust not found. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "[v] Rust installed successfully"
else
    echo "[v] Rust is already installed"
fi

# Check Rust version
echo "[*] Checking Rust version..."
rustc --version
cargo --version

# Build the project
echo ""
echo "[*] Building API Hunter (release mode)..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "[!] Build failed. Please check the error messages above."
    exit 1
fi

echo "[v] Build successful!"

# Install binary
echo ""
echo "[*] Installing binary to /usr/local/bin..."
sudo cp target/release/api_hunter /usr/local/bin/apihunter
sudo chmod +x /usr/local/bin/apihunter

echo "[v] Binary installed to /usr/local/bin/apihunter"

# Verify installation
echo ""
echo "[*] Verifying installation..."
if command -v apihunter &> /dev/null; then
    echo "[v] Installation successful!"
    echo ""
    echo "======================================================================"
    echo "  API Hunter is now installed and ready to use!"
    echo "======================================================================"
    echo ""
    echo "Usage:"
    echo "  apihunter scan <target> [options]"
    echo ""
    echo "Examples:"
    echo "  apihunter scan https://example.com --sV -T3"
    echo "  apihunter scan https://api.example.com --deep-js --sV --sA"
    echo ""
    echo "For more information, run: apihunter --help"
    echo ""
else
    echo "[!] Installation verification failed"
    exit 1
fi

# Optional: Install dependencies for advanced features
echo ""
read -p "Install optional dependencies (Tor, ChromeDriver)? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Installing optional dependencies..."
    
    # Detect distribution
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu/Kali
        sudo apt-get update
        sudo apt-get install -y tor chromium-driver
        echo "[v] Tor and ChromeDriver installed"
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        sudo dnf install -y tor chromium-chromedriver
        echo "[v] Tor and ChromeDriver installed"
    elif [ -f /etc/arch-release ]; then
        # Arch Linux
        sudo pacman -S --noconfirm tor chromium
        echo "[v] Tor and Chromium installed"
    else
        echo "[!] Unsupported distribution. Please install Tor and ChromeDriver manually."
    fi
fi

echo ""
echo "======================================================================"
echo "  Installation Complete!"
echo "======================================================================"
