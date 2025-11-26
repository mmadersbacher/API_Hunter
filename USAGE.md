# API Hunter - Usage Guide

## Professional CLI with nmap-style Flags

### Quick Start

```bash
# Fast passive scan
api_hunter scan example.com --lite

# Deep analysis with all features
api_hunter scan example.com --deep -T4

# Aggressive testing (requires authorization)
api_hunter scan example.com -A --sV --sA

# Ultra-deep endpoint testing
api_hunter test-endpoint https://api.example.com/users -F
```

## Scan Flags (nmap-inspired)

### Timing Templates (-T)
```bash
-T0  # Paranoid (concurrency: 1, per-host: 1)
-T1  # Sneaky (concurrency: 5, per-host: 1)
-T2  # Polite (concurrency: 15, per-host: 2)
-T3  # Normal (concurrency: 50, per-host: 6) [DEFAULT]
-T4  # Aggressive (concurrency: 100, per-host: 12)
-T5  # Insane (concurrency: 200, per-host: 20)
```

### Scan Modes

| Flag | Description | Includes |
|------|-------------|----------|
| `--lite` | Fast, passive scanning | Basic discovery, minimal concurrency |
| `--deep` | Deep analysis | Wayback + GAU + JS extraction + Vuln scanning |
| `-A, --aggressive` | Aggressive testing | Bruteforce, parameter fuzzing, IDOR testing |

### Vulnerability Scanning

| Flag | Description | Tests |
|------|-------------|-------|
| `--sV` | Scan for vulnerabilities (like nmap -sV) | SQLi, XSS, RCE, SSRF, Path Traversal |
| `--sA` | Scan for admin/debug endpoints | Admin panels, debug endpoints, sensitive paths |

### Additional Features

| Flag | Description |
|------|-------------|
| `-B, --browser` | Enable headless Chrome for JavaScript-based API discovery |
| `--browser-wait <MS>` | Browser wait time in milliseconds (default: 3000) |
| `--browser-depth <N>` | Crawl depth for multi-page discovery (default: 1) |
| `--anon` | Anonymous mode with residential proxies + human-like patterns |
| `--full-speed` | Disable delays in anonymous mode |
| `--bypass-waf` | Enable WAF bypass techniques |
| `-c, --concurrency <N>` | Override timing template concurrency |
| `--per-host <N>` | Override per-host limit |
| `-r, --retries <N>` | Number of retries (default: 3, max: 10) |
| `--timeout <SECS>` | Request timeout in seconds |
| `-o, --out <DIR>` | Output directory (default: ./results) |

## Test Phases (Logical Order)

The scanner executes tests in a professional, logical sequence:

### Phase 1: WAF Detection
- Passive WAF fingerprinting
- Detection of: Cloudflare, Akamai, Sucuri, Imperva, F5, Barracuda, FortiWeb

### Phase 2: API Discovery
- **Historical Data**: Wayback Machine, GAU (if `--deep`)
- **JavaScript Extraction**: Parse JS files for API endpoints
- **Browser Discovery**: Headless Chrome network monitoring (if `-B`)
- **Pattern Matching**: Filter API candidates

### Phase 3: Active Probing
- HTTP fingerprinting
- Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- CORS configuration checks
- Technology detection

### Phase 4: Vulnerability Scanning (if `--sV` or `--deep`)
- SQL Injection testing
- NoSQL Injection testing
- XSS (Cross-Site Scripting)
- SSRF (Server-Side Request Forgery)
- Path Traversal
- RCE (Remote Code Execution)

### Phase 5: Admin/Debug Discovery (if `--sA`)
- Admin panel scanning
- Debug endpoint enumeration
- Sensitive path discovery

### Phase 6: Aggressive Testing (if `-A`)
- Parameter fuzzing
- IDOR (Insecure Direct Object Reference) testing
- Bruteforce enumeration

### Phase 7: WAF Bypass (if `--bypass-waf`)
- Encoding techniques
- Header manipulation
- Request obfuscation

## Test Endpoint Command

Ultra-deep testing of a single endpoint with 8 phases:

```bash
api_hunter test-endpoint <URL> [OPTIONS]
```

### Options
| Flag | Description |
|------|-------------|
| `-F, --fuzz` | Include security fuzzing tests (SQLi, XSS, SSRF, etc.) |
| `-n, --rate-limit <N>` | Number of requests for rate limit testing (default: 100) |

### Example
```bash
# Test single endpoint with fuzzing
api_hunter test-endpoint https://api.example.com/users/123 -F -n 50
```

## Examples

### Example 1: Fast Passive Scan
```bash
api_hunter scan example.com --lite
```
- Uses T3 timing (8 concurrency, 2 per-host)
- No external tools (Wayback/GAU disabled)
- Basic discovery only

### Example 2: Deep Analysis
```bash
api_hunter scan example.com --deep -T4
```
- Aggressive timing (100 concurrency, 12 per-host)
- Wayback + GAU enabled
- Vulnerability scanning enabled
- JavaScript extraction

### Example 3: Full Security Assessment
```bash
api_hunter scan example.com --deep -A --sV --sA -B -T4
```
- Deep analysis with Wayback/GAU
- Aggressive testing (bruteforce, fuzzing, IDOR)
- Vulnerability scanning
- Admin endpoint discovery
- Browser-based discovery
- Aggressive timing

### Example 4: Anonymous Scanning
```bash
api_hunter scan example.com --deep --anon --full-speed
```
- Deep analysis
- Residential proxy routing
- Human-like request patterns
- Full-speed mode (no delays)

### Example 5: Ultra-Deep Endpoint Testing
```bash
api_hunter test-endpoint https://api.example.com/users/123 -F -n 100
```
- 8 test phases:
  - API docs discovery
  - GraphQL detection
  - WebSocket detection
  - HTTP methods testing
  - CORS testing
  - Rate limiting
  - Deep response analysis
  - Security fuzzing

## Output Files

| File | Description |
|------|-------------|
| `target_apis_sorted.csv` | All discovered APIs sorted by score |
| `target_apis_stream.csv` | APIs in discovery order |
| `target_raw.jsonl` | Raw JSON data for all endpoints |
| `target_top.txt` | Top-scored API endpoints |
| `analysis_summary.txt` | Security analysis summary (if `--sV` or `--deep`) |
| `analysis_results.json` | Detailed analysis JSON (if `--sV` or `--deep`) |
| `fuzz_results.txt` | Parameter fuzzing results (if `-A`) |

## Timing Comparison

| Mode | Concurrency | Per-Host | Speed | Use Case |
|------|-------------|----------|-------|----------|
| T0 (Paranoid) | 1 | 1 | Slowest | IDS/WAF evasion |
| T1 (Sneaky) | 5 | 1 | Very Slow | Stealth scanning |
| T2 (Polite) | 15 | 2 | Slow | Production systems |
| T3 (Normal) | 50 | 6 | Medium | General scanning |
| T4 (Aggressive) | 100 | 12 | Fast | Bug bounties |
| T5 (Insane) | 200 | 20 | Fastest | Authorized testing |

## Best Practices

1. **Start with `--lite`** for initial reconnaissance
2. **Use `--deep`** for comprehensive analysis
3. **Add `-A`** only with explicit authorization
4. **Combine flags** for powerful scans: `--deep -A --sV --sA -B -T4`
5. **Use `--anon`** when stealth is required
6. **Test endpoints individually** with `test-endpoint` for detailed analysis

## Ethical Usage

⚠️ **WARNING**: Only scan targets you own or have explicit permission to test.

- Aggressive modes (`-A`, `--bypass-waf`) require authorization
- Fuzzing tests may trigger WAF/IDS systems
- Use responsible timing templates on production systems
- Follow responsible disclosure practices

## Legal Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Users are responsible for complying with all applicable laws and obtaining proper authorization before scanning.
