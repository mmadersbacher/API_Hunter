#!/bin/bash
# API Hunter Update Script
# Updates API Hunter to the latest version from GitHub

set -e

echo "[*] API Hunter Update Script"
echo "============================================"
echo ""

# Check if we're in the API_Hunter directory
if [ ! -f "Cargo.toml" ] || ! grep -q "api_hunter" Cargo.toml 2>/dev/null; then
    echo "[!] Error: This script must be run from the API_Hunter directory"
    echo "[*] Navigate to your API_Hunter directory first:"
    echo "    cd ~/API_Hunter  # or wherever you installed it"
    exit 1
fi

# Check if apihunter is currently installed
if ! command -v apihunter &> /dev/null; then
    echo "[!] Warning: apihunter command not found in PATH"
    echo "[*] You may need to run install.sh instead"
    read -p "[?] Continue with update anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "[*] Fetching latest changes from GitHub..."
git fetch origin

# Check if there are updates
LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse @{u})

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "[v] Already up to date!"
    echo "[*] Current version: $(git log -1 --format=%h)"
else
    echo "[>] Updates available!"
    echo "[*] Pulling latest changes..."
    git pull origin master
    
    echo ""
    echo "[*] Building optimized release binary..."
    cargo build --release
    
    echo ""
    echo "[*] Installing to /usr/local/bin/apihunter..."
    sudo cp target/release/api_hunter /usr/local/bin/apihunter
    sudo chmod +x /usr/local/bin/apihunter
    
    echo ""
    echo "[v] Update complete!"
    echo "[*] New version: $(git log -1 --format=%h)"
    echo ""
    echo "[=] Changelog:"
    git log --oneline -5
fi

echo ""
echo "[*] Verifying installation..."
if command -v apihunter &> /dev/null; then
    echo "[v] apihunter is installed at: $(which apihunter)"
    echo ""
    echo "Test it with:"
    echo "  apihunter --help"
else
    echo "[!] Warning: apihunter not found in PATH"
    echo "[*] You may need to add /usr/local/bin to your PATH"
fi

echo ""
echo "============================================"
echo "[+] Done!"
