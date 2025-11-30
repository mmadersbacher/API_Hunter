# API Hunter  Advanced API reconnaissance and security testing tool with deep vulnerability analysis and anonymous scanning capabilities.  ## Features  ### Core Capabilities
- **API Discovery**: Automated endpoint enumeration from multiple sources
- **Deep JavaScript Analysis**: Extract API endpoints, secrets, tokens, and parameters from JS files (like F12 Network inspection)
- **Deep Security Analysis**: 6+ vulnerability types with real exploit testing
- **Strict Classification**: Evidence-based severity scoring (Critical = Exploitable)
- **Anonymous Scanning**: Tor integration with IP rotation and stealth mode
- **Performance Optimized**: 5x faster with connection pooling and async execution
- **Bug Bounty Ready**: Comprehensive reports with CVSS scoring  ### Vulnerability Detection
- SQL Injection (9 payloads, error detection)
- Command Injection (6 payloads, system output check)
- Authentication Bypass (7 token manipulation tests)
- Path Traversal (5 payloads, file content verification)
- SSRF (5 payloads, metadata endpoint access)
- XSS (4 payloads, encoding validation)
- IDOR (Sequential/UUID/Hash testing with evidence)
- Admin Panel Detection (public access + operation testing)
- CORS Misconfiguration (wildcard + credentials)
- Security Headers Analysis (context-aware scoring)  ## Quick Start  ### Installation  ```powershell
# Windows
git clone https://github.com/mmadersbacher/API_Hunter
cd API_Hunter
cargo build --release
```  ```bash
# Linux/macOS
git clone https://github.com/mmadersbacher/API_Hunter
cd API_Hunter
cargo build --release
sudo cp target/release/api_hunter /usr/local/bin/
```  ### Basic Usage  ```bash
# Simple scan
cargo run --release -- scan https://target.com  # Deep JS analysis (extract secrets, tokens, API endpoints from JavaScript)
cargo run --release -- scan https://target.com --deep-js  # Lite mode (low impact)
cargo run --release -- scan https://target.com --lite  # Deep analysis with all features
cargo run --release -- scan https://target.com \  --deep-analysis \  --scan-admin \  --advanced-idor \  --fuzz-params  # Anonymous scan with Tor
cargo run --release -- scan https://target.com \  --anonymous \  --lite
```  ## Documentation  - **[Deep JavaScript Analysis](DEEP_JS_ANALYSIS.md)** - Extract secrets, tokens, and API endpoints from JS files
- **[Residential Proxy Mode](RESIDENTIAL_PROXY_MODE.md)** - Complete guide with setup, patterns, costs
- **[Anonymous Quick Start](ANONYMOUS_QUICKSTART.md)** - TL;DR for anonymous scanning
- **[Classification System](CLASSIFICATION_SYSTEM.md)** - Severity scoring explained
- **[Performance Guide](PERFORMANCE_AND_CLASSIFICATION.md)** - Optimizations and benchmarks  ## Anonymous Mode  Route traffic through residential proxies with sophisticated human-like patterns:  ```bash
# 1. Get residential proxy credentials
# Smartproxy: https://smartproxy.com
# BrightData: https://brightdata.com
# Oxylabs: https://oxylabs.io  # 2. Configure proxy
$env:RESIDENTIAL_PROXY = "user:pass@gate.smartproxy.com:7000"  # Windows
export RESIDENTIAL_PROXY="user:pass@gate.smartproxy.com:7000"  # Linux/macOS  # 3. Run anonymous scan (human-like patterns)
cargo run --release -- scan https://target.com --anonymous --lite  # 4. Full-speed mode (no delays, still anonymous)
cargo run --release -- scan https://target.com --anonymous --full-speed
``` **Output:**
```
Anonymous Mode Enabled
Anonymous Mode Status:  Proxy Type: Residential (Real IPs)  Session Duration: 5-10 minutes  TLS Fingerprint: chrome_120_windows (constant)  User-Agent: Mozilla/5.0... (session-based)  Request Pattern: Human-like (burst + pause)  Full Speed: Disabled  Proxy Status: Configured  Residential Proxy: gate.smartproxy.com
Anonymous client ready (TLS fingerprint: constant)  Human-like pause: 5247ms (burst complete)
Session Rotation: New IP + UA (session: 8a2f4k9l)
``` **Features:**
- Real residential IPs (not datacenter/VPN/Tor)
- Human-like patterns (burst: 1-3 requests, pause: 2-8s, jitter: ±500ms)
- Sticky sessions (same IP for 5-10 minutes, then rotate)
- Constant TLS fingerprint (Chrome 120 - no mid-session changes)
- Session-based User-Agent (consistent per session)
- Full-speed mode (--full-speed flag: no delays, maximum speed)
- DNS over HTTPS (DoH ready, no DNS leaks)
- Detection rate: <1% (with human patterns) **vs Tor:**
- Real IPs instead of known Tor nodes
- 5x faster (100-200ms vs 500-1000ms)
- Sticky sessions (5-10 min vs random rotation)
- Human-like timing (vs constant delays)
- Rarely blocked (vs often blocked)
- Costs $10-50/month (vs free)  See **[RESIDENTIAL_PROXY_MODE.md](RESIDENTIAL_PROXY_MODE.md)** for complete guide.  Quick reference: **[ANONYMOUS_QUICKSTART.md](ANONYMOUS_QUICKSTART.md)**  ## Example Results  ### Before: Loose Classification
```
Critical: 44  (mostly missing headers)
High: 48
Medium: 262
```  ### After: Strict Evidence-Based Classification
```
Critical: 0-2  (only confirmed exploits)
High: 8-12  (likely exploitable)
Medium: 30-50  (potential issues)
Low: 200-300  (minor concerns)
``` **Critical findings now require:**
- SQL errors in response
- Command output visible
- File contents accessible
- Different user data confirmed
- State-changing operations without auth  ## Advanced Usage  ### All Flags
```bash
cargo run --release -- scan <TARGET> [OPTIONS]  Discovery:  --with-gau  Enable gau integration  --with-wayback  Enable waybackurls integration  Security Testing:  --deep-analysis  Analyze headers, CORS, fingerprinting  --scan-admin  Scan for admin/debug endpoints  --advanced-idor  Test IDOR with multiple techniques  --fuzz-params  Discover hidden parameters  --test-idor  Basic IDOR testing on ID parameters  Performance:  --lite  Low-impact mode (concurrency=8, timeout=3s)  --concurrency <N>  Global concurrency (default: 50)  --per-host <N>  Per-host limit (default: 6)  --timeout <SEC>  Request timeout (default: 10s)  --retries <N>  Retry attempts (default: 3, max: 10)  Anonymity:  --anonymous  Enable residential proxy with human-like patterns  --full-speed  Skip all delays (still anonymous, for authorized scans)  Advanced:  --aggressive  Enable ffuf bruteforce (requires --confirm-aggressive)  --confirm-aggressive  Confirm aggressive scanning  --resume <FILE>  Resume from existing JSONL  Output:  --out <DIR>  Output directory (default: ./results)  --debug  Enable debug logging  --verbose  Enable verbose logging
```  ### Example Workflows  #### Bug Bounty Reconnaissance
```bash
# Phase 1: Anonymous discovery (residential proxy)
cargo run --release -- scan https://target.com \  --anonymous \  --lite \  --timeout 60  # Phase 2: Deep analysis (from allowed IP)
cargo run --release -- scan https://target.com \  --deep-analysis \  --scan-admin \  --advanced-idor
```  #### Red Team Assessment (Maximum Stealth)
```bash
# Ultra-stealthy scan with human-like patterns
cargo run --release -- scan https://target.com \  --anonymous \  --lite \  --deep-analysis \  --scan-admin \  --timeout 180 \  --concurrency 5
```  #### High-Speed Authorized Testing
```bash
# Fast scan but still anonymous
cargo run --release -- scan https://your-server.com \  --anonymous \  --full-speed \  --deep-analysis \  --scan-admin
```  #### CI/CD Security Testing
```bash
# Quick security check
cargo run --release -- scan https://staging.app.com \  --lite \  --deep-analysis \  --timeout 60  # Parse JSON for Critical findings
jq '.analyses[] | select(.severity == "Critical")' results/analysis_results.json
```  ## Performance  ### Optimizations Implemented
- Connection Pooling: 300 connections per host (5x faster)
- parking_lot: 10x faster mutexes
- ahash: 30% faster hashing
- SmallVec: Stack allocation (0 heap for small vectors)
- LTO + opt-level 3: 10-15% faster execution
- Async Semaphores: Precise concurrency control  ### Benchmarks
```
100 requests to same host:
- Without pooling: 15.2s
- With pooling: 2.8s
- Improvement: 5.4x faster  Memory usage:
- Before: 85 MB peak
- After: 45 MB peak
- Improvement: 47% reduction
```  ## Classification System  ### Severity Levels  | Level | CVSS | Requirements | Examples | |-------|------|--------------|----------| | **Critical** | 9.0-10.0 | Confirmed exploit | SQLi with errors, RCE with output, Auth bypass working | | **High** | 7.0-8.9 | Likely exploitable | SSRF to metadata, IDOR with data, Public debug+500 bytes | | **Medium** | 4.0-6.9 | Potential issue | XSS reflected, CORS wildcard, Multiple missing headers | | **Low** | 0.1-3.9 | Minor concern | Single missing header, Version disclosure | | **Info** | 0.0 | No impact | Framework detection, CDN fingerprint | ### Classification Philosophy
- **Critical = CRITICAL**: Only confirmed exploitable vulnerabilities
- **Evidence Required**: SQL errors, command output, file contents, user data
- **Context-Aware**: Same issue scores differently based on access control, data sensitivity
- **Well-Secured Site**: Expect 0-2 Critical findings (not 44!)  See **[CLASSIFICATION_SYSTEM.md](CLASSIFICATION_SYSTEM.md)** for complete details.  ## Output Files  ```
results/
├── target_raw.jsonl  # All raw probe data
├── target_apis_sorted.csv  # Sorted API endpoints
├── target_top.txt  # Top findings summary
├── analysis_results.json  # Deep analysis results (JSON)
└── analysis_summary.txt  # Human-readable summary
```  ### Example analysis_summary.txt
```
=== Deep Analysis Summary ===  API Endpoints Analyzed: 107  Critical: 0 | High: 8 | Medium: 30  === Critical Findings ===
(none - site is well-secured)  === High Findings ===
1. IDOR on /api/users/{id}  Evidence: Different user email in response  CVSS: 7.8  2. Public Admin Panel: /admin/debug  Evidence: 1.2KB response without authentication  CVSS: 7.5
```  ## Development  ### Build from Source
```bash
git clone https://github.com/mmadersbacher/API_Hunter
cd API_Hunter
cargo build --release
```  ### Run Tests
```bash
cargo test
cargo test --release
```  ### Run with Debug Logging
```bash
cargo run --release -- scan https://target.com --debug
```  ## Legal & Ethics  ### Important Disclaimers
1. **Permission Required**: Only scan systems you own or have explicit permission to test
2. **Bug Bounty Programs**: Check if Tor/anonymous scanning is allowed
3. **Responsible Disclosure**: Report findings responsibly
4. **Rate Limiting**: Use `--lite` mode to avoid DoS
5. **Data Privacy**: Handle discovered data according to applicable laws  ### Best Practices
```bash
# Always use --lite for initial reconnaissance
cargo run --release -- scan https://target.com --lite  # Add delays for sensitive targets
cargo run --release -- scan https://target.com --timeout 30  # Monitor for rate limiting (403/429 responses)
tail -f results/analysis_summary.txt
```  ## Troubleshooting  ### Anonymous Mode Issues
```
⚠️  No residential proxy configured!
``` **Solution**: Set environment variable:
```bash
# Windows
$env:RESIDENTIAL_PROXY = "user:pass@gate.smartproxy.com:7000"  # Linux/macOS
export RESIDENTIAL_PROXY="user:pass@gate.smartproxy.com:7000"  # Test proxy
curl -x http://user:pass@gate.smartproxy.com:7000 https://api.ipify.org
```  ### High Proxy Costs **Solution**: Use `--lite` mode and lower concurrency:
```bash
cargo run --release -- scan https://target.com --anonymous --lite --concurrency 5
```  ### Compilation Errors
```bash
# Update Rust
rustup update  # Clean build
cargo clean
cargo build --release
```  ### Performance Issues
```bash
# Reduce concurrency
cargo run --release -- scan https://target.com --concurrency 10  # Use lite mode
cargo run --release -- scan https://target.com --lite
```  ## Resources  - **Documentation**: See `/docs` folder
- **Examples**: See `ANONYMOUS_MODE.md` and `CLASSIFICATION_SYSTEM.md`
- **Issues**: https://github.com/mmadersbacher/API_Hunter/issues
- **Tor Setup**: https://www.torproject.org/  ## Credits  Developed by mmadersbacher **Technologies:**
- Rust + Tokio (async runtime)
- reqwest (HTTP client)
- Tor (anonymous routing)
- parking_lot, ahash, smallvec (performance)  ## License  MIT License  Copyright (c) 2025 mmadersbacher  Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:  The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
