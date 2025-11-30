# API Hunter

```
                 _    ____ ___   _   _ _   _ _   _ _____ _____ ____  
                / \  |  _ \_ _| | | | | | | | \ | |_   _| ____|  _ \ 
               / _ \ | |_) | |  | |_| | | | |  \| | | | |  _| | |_) |
              / ___ \|  __/| |  |  _  | |_| | |\  | | | | |___|  _ < 
             /_/   \_\_|  |___| |_| |_|\___/|_| \_| |_| |_____|_| \_\
                                                                      
                          Security Scanner v0.1.0
```

A comprehensive API security scanner and reconnaissance tool for bug bounty hunters and security researchers.

## Features

- `[*]` **API Discovery** - Subdomain enumeration, API endpoint discovery, JavaScript analysis
- `[>]` **Active Probing** - Smart HTTP probing with rate limiting and WAF detection
- `[!]` **Vulnerability Scanning** - Automatic XSS, SQLi, IDOR, SSRF, and more
- `[DIR]` **Deep JS Analysis** - Extract API endpoints, secrets, tokens, parameters from JS files
- `[+]` **Advanced Testing** - Automatic XSS testing with 24+ payloads when vulnerabilities detected
- `[=]` **Structured Reports** - Clean CLI output + detailed JSON/TXT reports
- `[~]` **Anonymity** - Tor integration and residential proxy support
- `[#]` **WAF Bypass** - Intelligent WAF detection and bypass techniques

## Installation

### Quick Install (Linux/Kali)

```bash
# Clone the repository
git clone https://github.com/mmadersbacher/API_Hunter.git
cd API_Hunter

# Run installation script
chmod +x install.sh
./install.sh

# Verify installation (can be run from ANY directory)
apihunter --help
```

**The `apihunter` command works from any directory, just like `nmap`!**

### Manual Installation

```bash
# Install dependencies first (REQUIRED)
# Kali/Debian/Ubuntu:
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev curl

# Fedora/RHEL:
sudo dnf install -y gcc openssl-devel pkg-config curl

# Arch Linux:
sudo pacman -S base-devel openssl pkg-config curl

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build from source
cargo build --release

# Install binary (works from any directory)
sudo cp target/release/api_hunter /usr/local/bin/apihunter
sudo chmod +x /usr/local/bin/apihunter

# Verify (try from home directory)
cd ~
apihunter --help
```

### Kali Linux (Detailed)

```bash
# Update system
sudo apt-get update

# Install ALL dependencies
sudo apt-get install -y build-essential pkg-config libssl-dev curl tor chromium-driver

# Clone and install
git clone https://github.com/mmadersbacher/API_Hunter.git
cd API_Hunter
chmod +x install.sh
./install.sh

# Test from any directory
cd /tmp
apihunter scan https://example.com -T3
```

## Update to Latest Version

### Quick Update (Recommended)

```bash
# Navigate to your API_Hunter directory
cd API_Hunter

# Run update script
chmod +x update.sh
./update.sh
```

### Manual Update

```bash
# Navigate to your API_Hunter directory
cd API_Hunter

# Pull latest changes
git pull origin master

# Rebuild and reinstall
cargo build --release
sudo cp target/release/api_hunter /usr/local/bin/apihunter

# Verify new version
apihunter --version
```

### Alternative: Fresh Install

```bash
# Remove old installation
sudo rm /usr/local/bin/apihunter

# Remove old directory
cd ~
rm -rf API_Hunter

# Clone and install fresh
git clone https://github.com/mmadersbacher/API_Hunter.git
cd API_Hunter
chmod +x install.sh
./install.sh
```

## Usage

### Basic Scan

```bash
apihunter scan https://example.com --sV -T3
```

### Deep Security Audit

```bash
apihunter scan https://example.com --deep-js --sV --sA -T3 --report findings.txt
```

### Aggressive Testing (with permission)

```bash
apihunter scan https://target.com --deep-js --sV --sA --aggressive -T4 --report audit.json
```

### Anonymous Scanning

```bash
apihunter scan https://target.com --anonymous --sV -T2
```

## Command Line Options

### Scan Modes

- `--sV` - Enable vulnerability scanning
- `--sA` - Enable admin/debug endpoint scanning  
- `--deep-js` - Deep JavaScript analysis (secrets, endpoints, tokens)
- `--aggressive` - Advanced IDOR and parameter fuzzing
- `--deep` - Enable all discovery modules (Wayback, GAU, etc.)

### Timing Profiles (like nmap)

- `-T0` - Paranoid (slowest, most stealthy)
- `-T1` - Sneaky
- `-T2` - Polite
- `-T3` - Normal (default, recommended)
- `-T4` - Aggressive
- `-T5` - Insane (fastest, most intrusive)

### Output Options

- `--report <file>` - Save detailed findings to JSON or TXT file
- `--out <dir>` - Output directory (default: ./results)

### Anonymity

- `--anonymous` - Route through Tor network
- `--residential` - Use residential proxies (requires config)

## Output Example

```
                 _    ____ ___   _   _ _   _ _   _ _____ _____ ____  
                / \  |  _ \_ _| | | | | | | | \ | |_   _| ____|  _ \ 
               / _ \ | |_) | |  | |_| | | | |  \| | | | |  _| | |_) |
              / ___ \|  __/| |  |  _  | |_| | |\  | | | | |___|  _ < 
             /_/   \_\_|  |___| |_| |_|\___/|_| \_| |_| |_____|_| \_\
                                                                      
                          Security Scanner v0.1.0

[>] Target: https://example.com
[~] Timing: T3 (concurrency: 50, per-host: 6)

[*] API discovery...
   [DIR] Deep JS analysis...
      Endpoints: 23 | Secrets: 5 [!] | Parameters: 67
      [!] 5 secrets found! Check ./results/js_critical_info.json
   Found: 107 URLs -> 8 API candidates

[>] Probing endpoints...

[*] Vulnerability scanning...
   [+] Auto-testing XSS on: https://example.com/search
      [v] Found 3 exploitable XSS vectors
   Findings: 2 [!] 8 [!!] 23 [i]

============================================================
              SCAN COMPLETE
============================================================

[*] Summary:
   Target: example.com
   Duration: 45s
   Endpoints: 15

[*] Security Findings:
   [!] CRITICAL 2
   [!!] HIGH 8
   [i] MEDIUM 23

[=] Results saved to: ./results
   [-] Report saved to: findings.txt
```

## Severity Levels

| Symbol | Severity | CVSS | Examples |
|--------|----------|------|----------|
| `[!]` | CRITICAL | 9.0+ | SQLi, RCE, Auth Bypass, Direct Data Exposure |
| `[!!]` | HIGH | 7.0-8.9 | IDOR with data access, SSRF, XXE, File Read |
| `[i]` | MEDIUM | 4.0-6.9 | XSS, CSRF, Info Disclosure, Path Traversal |
| `[.]` | LOW | 0.1-3.9 | Missing headers, Version disclosure |

## Automatic XSS Testing

When XSS vulnerabilities are detected, API Hunter automatically:

- Tests 24 different XSS payload types
- Checks 10 common parameter names
- Runs 250+ test combinations
- Saves confirmed exploits to `./results/xss_findings.json`

Example:
```
[*] Vulnerability scanning...
   [+] Auto-testing XSS on: https://example.com/search
      [v] Found 3 exploitable XSS vectors
   [=] XSS findings saved to: ./results/xss_findings.json
```

## Output Files

All results are saved to `./results/`:

| File | Description |
|------|-------------|
| `analysis_results.json` | Complete analysis data (JSON) |
| `analysis_summary.txt` | Human-readable summary |
| `js_critical_info.json` | Deep JS analysis results |
| `xss_findings.json` | Automatic XSS test results |
| `target_apis_sorted.csv` | Discovered API endpoints |
| `subdomains.txt` | Discovered subdomains |

## Advanced Features

### Deep JavaScript Analysis

Extracts 12 different types of critical information from JavaScript files:

1. API Endpoints (fetch, axios, XMLHttpRequest, jQuery)
2. Secrets & Tokens (API keys, JWT, AWS keys, passwords)
3. Parameters (query, path, body, header)
4. GraphQL endpoints, queries, mutations
5. WebSocket URLs
6. Cloud Storage (S3, GCS, Azure, Cloudflare R2)
7. Email addresses
8. Domain references
9. API routes
10. Comments & TODOs
11. Third-party integrations (Stripe, PayPal, Google, etc.)
12. Version numbers

### WAF Detection

Automatically detects and reports Web Application Firewalls:

- Cloudflare
- AWS WAF
- Akamai
- Imperva
- ModSecurity
- F5 BIG-IP
- Barracuda
- Sucuri
- And many more...

### Anonymity Features

**Tor Integration:**
```bash
apihunter scan https://target.com --anonymous --sV -T1
```

**Residential Proxies:**
```bash
apihunter scan https://target.com --residential --sV -T2
```

## Best Practices

### Bug Bounty Hunting

```bash
# Step 1: Initial reconnaissance
apihunter scan https://target.com --deep-js -T2

# Step 2: Review discovered endpoints
cat ./results/js_critical_info.json

# Step 3: Full vulnerability scan
apihunter scan https://api.target.com --sV --sA -T3 --report bounty.txt
```

### Security Audits

```bash
# Comprehensive audit with all features
apihunter scan https://client.com \
  --deep-js \
  --sV \
  --sA \
  --aggressive \
  -T2 \
  --report security_audit.txt
```

### Rate Limit Avoidance

- Start with `-T0` or `-T1` (slowest)
- Use `--anonymous` flag for Tor routing
- Add delays between scans
- Respect robots.txt and terms of service

## Performance

### Timing Profiles

- **T0 (Paranoid)**: 1 concurrent, 1 per-host, 1 retry
- **T1 (Sneaky)**: 5 concurrent, 1 per-host, 2 retries
- **T2 (Polite)**: 15 concurrent, 2 per-host, 2 retries
- **T3 (Normal)**: 50 concurrent, 6 per-host, 3 retries (recommended)
- **T4 (Aggressive)**: 100 concurrent, 12 per-host, 3 retries
- **T5 (Insane)**: 200 concurrent, 20 per-host, 1 retry

### Timeouts

- 10s per HTTP request
- 120s vulnerability scan timeout
- 2MB max JS file size limit

## Requirements

- **Rust** 1.70+ (installed automatically by install.sh)
- **OpenSSL** development files (libssl-dev on Debian/Ubuntu) - **REQUIRED**
- **pkg-config** - **REQUIRED**
- **build-essential** (gcc, make, etc.) - **REQUIRED**
- **Optional**: Tor (for --anonymous mode)
- **Optional**: ChromeDriver (for --browser mode)

## Troubleshooting

### Error: "Could not find directory of OpenSSL installation"

**Solution:**
```bash
# Kali/Debian/Ubuntu:
sudo apt-get install -y libssl-dev pkg-config build-essential

# Fedora/RHEL:
sudo dnf install -y openssl-devel pkg-config gcc

# Arch Linux:
sudo pacman -S openssl pkg-config base-devel

# Then rebuild:
cd ~/API_Hunter
cargo clean
cargo build --release
sudo cp target/release/api_hunter /usr/local/bin/apihunter
```

### Error: "apihunter: command not found"

**Solution 1 - PATH issue:**
```bash
# Check if binary exists
ls -la /usr/local/bin/apihunter

# If it exists, add to PATH:
export PATH="/usr/local/bin:$PATH"

# Make it permanent:
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Solution 2 - Reinstall:**
```bash
cd ~/API_Hunter
sudo cp target/release/api_hunter /usr/local/bin/apihunter
sudo chmod +x /usr/local/bin/apihunter
```

### Error: "cargo: command not found" after installing Rust

**Solution:**
```bash
# Source Rust environment
source $HOME/.cargo/env

# Or restart your terminal
```

### Build takes forever or fails

**Solution:**
```bash
# Try with more verbose output
RUST_BACKTRACE=1 cargo build --release

# Or try clean build
cargo clean
cargo build --release
```

## Documentation

- `README.md` - This file
- `USAGE.md` - Detailed usage guide
- `QUICK_REFERENCE.md` - Quick reference guide

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Disclaimer

This tool is for security research and authorized testing only. Always obtain proper authorization before scanning targets you do not own. Unauthorized access to computer systems is illegal.

## License

MIT License - See LICENSE file for details

## Author

**mmadersbacher**
- GitHub: [@mmadersbacher](https://github.com/mmadersbacher)

## Acknowledgments

- Built with Rust and Tokio
- Inspired by tools like httpx, nuclei, and nmap
- Thanks to the bug bounty and security research community

---

**Happy Hunting!**

For issues, questions, or feature requests, please open an issue on GitHub.
