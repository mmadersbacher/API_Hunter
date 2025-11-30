# API Hunter - Kali Linux Installation Guide

## Quick Start (Copy & Paste)

```bash
# Step 1: Install dependencies (REQUIRED)
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev curl

# Step 2: Clone and install
git clone https://github.com/mmadersbacher/API_Hunter.git
cd API_Hunter
chmod +x install.sh
./install.sh

# Step 3: Test from ANY directory (like nmap)
cd ~
apihunter --help
apihunter scan https://example.com -T3
```

## What Gets Installed

- **Rust toolchain** (if not present)
- **API Hunter binary** at `/usr/local/bin/apihunter`
- Command works from **any directory** (just like `nmap`, `gobuster`, `ffuf`)

## Post-Installation

### Test Installation

```bash
# From any directory:
cd /tmp
apihunter --help

# Quick scan:
apihunter scan https://httpbin.org -T3

# Full security audit:
apihunter scan https://example.com --deep-js --sV --sA -T3 --report findings.txt
```

### Optional Tools

```bash
# For anonymous scanning (--anonymous flag)
sudo apt-get install -y tor
sudo systemctl start tor

# For browser-based discovery (--browser flag)
sudo apt-get install -y chromium-driver
```

## Common Issues & Fixes

### Issue 1: "Could not find directory of OpenSSL installation"

**Cause:** Missing OpenSSL development files

**Fix:**
```bash
sudo apt-get install -y libssl-dev pkg-config build-essential
cd ~/API_Hunter
cargo clean
cargo build --release
sudo cp target/release/api_hunter /usr/local/bin/apihunter
```

### Issue 2: "apihunter: command not found"

**Fix 1 - Check installation:**
```bash
ls -la /usr/local/bin/apihunter
# If file exists, continue to Fix 2
```

**Fix 2 - PATH issue:**
```bash
export PATH="/usr/local/bin:$PATH"
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc  # For Kali's default Zsh
source ~/.zshrc
```

**Fix 3 - Reinstall binary:**
```bash
cd ~/API_Hunter
sudo cp target/release/api_hunter /usr/local/bin/apihunter
sudo chmod +x /usr/local/bin/apihunter
```

### Issue 3: "cargo: command not found" after Rust installation

**Fix:**
```bash
source $HOME/.cargo/env
# Then try installation again
cd ~/API_Hunter
./install.sh
```

### Issue 4: Build fails with "linker error"

**Fix:**
```bash
sudo apt-get install -y gcc g++ make
cd ~/API_Hunter
cargo clean
cargo build --release
```

## Usage Examples

### Basic Reconnaissance

```bash
# Quick scan (from any directory)
apihunter scan https://target.com -T3

# With subdomain enumeration
apihunter scan https://target.com --subdomains -T2

# Deep JavaScript analysis (extract secrets, tokens, API endpoints)
apihunter scan https://target.com --deep-js -T3
```

### Security Testing

```bash
# Vulnerability scanning
apihunter scan https://target.com --sV -T3

# Admin panel detection
apihunter scan https://target.com --sA -T3

# Full security audit
apihunter scan https://target.com --deep-js --sV --sA -T3 --report audit.txt

# Aggressive testing (with permission)
apihunter scan https://target.com --aggressive --sV --sA -T4
```

### Stealth Mode

```bash
# Anonymous via Tor (requires tor service)
sudo systemctl start tor
apihunter scan https://target.com --anonymous --sV -T1

# Polite/slow scanning to avoid detection
apihunter scan https://target.com --sV -T0
```

### Bug Bounty Workflow

```bash
# Step 1: Initial recon
apihunter scan https://target.com --deep-js -T2 --report recon.txt

# Step 2: Review findings
cat ./results/js_critical_info.json

# Step 3: Deep security testing
apihunter scan https://api.target.com --sV --sA -T3 --report vulnerabilities.txt

# Step 4: Check for specific issues
cat ./results/xss_findings.json
cat ./results/analysis_summary.txt
```

## Timing Profiles (like nmap)

```bash
# -T0: Paranoid (1 concurrent, ultra-slow, most stealthy)
apihunter scan https://target.com --sV -T0

# -T1: Sneaky (5 concurrent, very slow)
apihunter scan https://target.com --sV -T1

# -T2: Polite (15 concurrent, slow, recommended for production)
apihunter scan https://target.com --sV -T2

# -T3: Normal (50 concurrent, balanced - default)
apihunter scan https://target.com --sV -T3

# -T4: Aggressive (100 concurrent, fast)
apihunter scan https://target.com --sV -T4

# -T5: Insane (200 concurrent, fastest, most intrusive)
apihunter scan https://target.com --sV -T5
```

## Output Files

All results saved to `./results/` in current directory:

```bash
# View results
cat ./results/analysis_summary.txt
cat ./results/js_critical_info.json
cat ./results/xss_findings.json
cat ./results/target_apis_sorted.csv

# Or with custom output directory
apihunter scan https://target.com --sV -T3 --out /tmp/scan_results
```

## Integration with Other Tools

### Piping to other tools

```bash
# Extract API endpoints for further testing
cat ./results/target_apis_sorted.csv | cut -d',' -f1 > endpoints.txt

# Feed endpoints to ffuf
cat endpoints.txt | while read url; do
    ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
done

# Feed to nuclei
cat endpoints.txt | nuclei -t ~/nuclei-templates/
```

### Using with proxies (Burp Suite)

```bash
# Set proxy environment variable
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Scan through Burp
apihunter scan https://target.com --sV -T3
```

## Uninstallation

```bash
# Remove binary
sudo rm /usr/local/bin/apihunter

# Remove source code
rm -rf ~/API_Hunter

# Remove Rust (optional)
rustup self uninstall
```

## Getting Help

```bash
# General help
apihunter --help

# Scan command help
apihunter scan --help

# Check version
apihunter --version
```

## System Requirements

- **OS:** Kali Linux 2023.1+ (also works on Ubuntu, Debian, Parrot OS)
- **RAM:** 512MB minimum, 2GB recommended
- **Disk:** 2GB for Rust + dependencies
- **Network:** Internet connection for installation

## Performance Tips

### Faster Scans

```bash
# Use higher timing profile
apihunter scan https://target.com --sV -T4

# Skip deep JS analysis if not needed
apihunter scan https://target.com --sV -T4 --no-deep-js
```

### Lower Resource Usage

```bash
# Use lite mode
apihunter scan https://target.com --lite

# Lower timing profile
apihunter scan https://target.com --sV -T1
```

## Security Notes

- Always obtain proper authorization before scanning
- Use `-T0` or `-T1` to avoid rate limits
- Use `--anonymous` flag for additional privacy
- Respect robots.txt and terms of service
- Some WAFs may block aggressive scans

## Updates

```bash
# Update to latest version
cd ~/API_Hunter
git pull origin master
cargo build --release
sudo cp target/release/api_hunter /usr/local/bin/apihunter
```

## Support

- **GitHub Issues:** https://github.com/mmadersbacher/API_Hunter/issues
- **Documentation:** See README.md and other .md files in repo
- **Examples:** Check QUICK_REFERENCE.md

---

**Happy Hunting from Kali Linux!**

Remember: With great power comes great responsibility. Only scan targets you have permission to test.
