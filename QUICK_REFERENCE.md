# API Hunter - Quick Reference Guide

## 🚀 Quick Start

### Basic Scan
```bash
api_hunter scan https://example.com --sV -T3
```

### Full Security Audit
```bash
api_hunter scan https://example.com --deep-js --sV --sA -T3 --report audit.txt
```

---

## 📊 Output Format

### Clean CLI Output
```
┌──────────────────────────────────────────────────┐
│          API Hunter - Security Scanner           │
└──────────────────────────────────────────────────┘

🎯 Target: https://example.com
⚡ Timing: T3 (concurrency: 50, per-host: 6)

🔍 API discovery...
   📁 Deep JS analysis...
      Endpoints: 23 | Secrets: 5 ⚠️ | Parameters: 67
      ⚠️  5 secrets found! Check ./results/js_critical_info.json
   Found: 107 URLs → 8 API candidates

🎯 Probing endpoints...

🔍 Vulnerability scanning...
   🔬 Auto-testing XSS on: https://example.com/search
      ✓ Found 3 exploitable XSS vectors
   Findings: 2 🔴 8 🟠 23 🟡

═══════════════════════════════════════════════════
              SCAN COMPLETE
═══════════════════════════════════════════════════

📊 Summary:
   Target: example.com
   Duration: 45s
   Endpoints: 15

🔍 Security Findings:
   🔴 CRITICAL 2
   🟠 HIGH 8
   🟡 MEDIUM 23

💾 Results saved to: ./results
   📄 Report saved to: audit.txt
```

---

## 🎯 Severity Levels

| Symbol | Severity | CVSS | Examples |
|--------|----------|------|----------|
| 🔴 | **CRITICAL** | 9.0+ | SQLi, RCE, Auth Bypass |
| 🟠 | **HIGH** | 7.0-8.9 | IDOR, SSRF, XXE |
| 🟡 | **MEDIUM** | 4.0-6.9 | XSS, CSRF, Info Leak |
| 🔵 | **LOW** | 0.1-3.9 | Missing Headers |

---

## 🔧 Command Flags

### Scan Modes
- `--sV` - Enable vulnerability scanning
- `--sA` - Enable admin/debug endpoint scanning
- `--deep-js` - Deep JavaScript analysis (extracts secrets, endpoints, etc.)
- `--aggressive` - Advanced IDOR testing

### Timing Profiles
- `-T0` - Paranoid (slowest, 5 concurrent)
- `-T1` - Sneaky (10 concurrent)
- `-T2` - Polite (20 concurrent)
- `-T3` - Normal (50 concurrent) ⭐ **Recommended**
- `-T4` - Aggressive (100 concurrent)
- `-T5` - Insane (200 concurrent, fastest)

### Output Control
- `--report <file>` - Save detailed findings to file (.txt or .json)
- No flag = Clean CLI output only

### Anonymity
- `--anonymous` - Route through Tor network
- `--residential` - Use residential proxies

---

## 📁 Output Files

All results saved to `./results/`:

| File | Description |
|------|-------------|
| `analysis_results.json` | Complete analysis data (JSON) |
| `analysis_summary.txt` | Human-readable summary |
| `js_critical_info.json` | Deep JS analysis results |
| `xss_findings.json` | Automatic XSS test results |
| `subdomains.txt` | Discovered subdomains |

---

## 🔬 Automatic XSS Testing

### When It Triggers
Automatically runs when:
- "Missing CSP - vulnerable to XSS" detected
- XSS-related findings in security headers
- Reflected parameters detected

### What It Tests
- **24 different XSS payloads**
- **10 common parameter names**
- **250+ test combinations per endpoint**

### Example Output
```
🔬 Auto-testing XSS on: https://example.com/search
   ✓ Found 3 exploitable XSS vectors
💾 XSS findings saved to: ./results/xss_findings.json
```

---

## 📊 Report Example

### Text Report
```
═══════════════════════════════════════════════════════
                    SECURITY SCAN REPORT
═══════════════════════════════════════════════════════

Target: example.com
Duration: 45s
Endpoints Tested: 15

Security Findings:
  🔴 CRITICAL: 2
  🟠 HIGH: 8
  🟡 MEDIUM: 23
  🔵 LOW: 12

═══════════════════════════════════════════════════════
                      FINDINGS DETAIL
═══════════════════════════════════════════════════════

🔴 CRITICAL - SQL Injection
URL: https://example.com/api/user?id=1
Evidence: SQL error with payload: ' OR '1'='1
CVSS: 9.8
Remediation: Use parameterized queries/prepared statements
```

---

## 💡 Best Practices

### For Bug Bounty Hunting
```bash
# Step 1: Discovery
api_hunter scan https://target.com --deep-js -T2

# Step 2: Full scan on interesting endpoints
api_hunter scan https://api.target.com --sV --sA -T3 --report findings.json

# Step 3: Aggressive testing (if allowed)
api_hunter scan https://api.target.com --sV --sA --aggressive -T4 --report critical.json
```

### For Security Audits
```bash
# Comprehensive audit with all features
api_hunter scan https://client.com \
  --deep-js \
  --sV \
  --sA \
  --aggressive \
  -T2 \
  --report security_audit_$(date +%Y%m%d).txt
```

### For Continuous Monitoring
```bash
# Quick scan (run daily)
api_hunter scan https://production-api.com --sV -T3 --report daily_scan.txt
```

---

## ⚡ Performance Tips

### Faster Scans
- Use `-T4` or `-T5` for faster scanning
- Skip `--deep-js` if not needed
- Avoid `--aggressive` mode for quick checks

### More Thorough Scans
- Use `-T0` or `-T1` to avoid rate limits
- Enable `--deep-js` for complete JS analysis
- Use `--aggressive` for advanced IDOR testing

### Rate Limit Avoidance
- Start with `-T0` (paranoid)
- Use `--anonymous` flag
- Add delays between scans

---

## 🐛 Troubleshooting

### Scan Times Out
```
⚠️  Vulnerability scan timed out after 120s
```
**Solution:** Use faster timing profile (`-T4` or `-T5`)

### Too Much Output
**Solution:** Use `--report` flag to save details to file

### Connection Refused Errors
```
WARN Failed to analyze: connection refused
```
**Solution:** Target may be blocking requests, try `--anonymous`

### No Findings
**Solution:** 
- Target may have good security
- Try `--deep-js` for hidden endpoints
- Enable `--sA` for admin paths

---

## 📚 Resources

### Documentation
- `README.md` - General overview
- `IMPROVEMENTS_COMPLETED.md` - Recent changes
- `USAGE.md` - Detailed usage guide

### Results Files
- `./results/analysis_summary.txt` - Quick overview
- `./results/analysis_results.json` - Complete data
- `./results/xss_findings.json` - XSS vulnerabilities

---

## 🔥 Common Workflows

### Workflow 1: Quick Vulnerability Check
```bash
api_hunter scan https://target.com --sV -T3
# Takes ~30-60 seconds
```

### Workflow 2: Deep Security Audit
```bash
api_hunter scan https://target.com --deep-js --sV --sA -T2 --report audit.txt
# Takes 5-15 minutes
# Generates detailed report
```

### Workflow 3: Aggressive Penetration Test
```bash
api_hunter scan https://target.com --deep-js --sV --sA --aggressive -T4 --report pentest.json
# Takes 10-30 minutes
# Maximum coverage
```

### Workflow 4: Bug Bounty Recon
```bash
# Phase 1: Asset Discovery
api_hunter scan https://target.com --deep-js -T2

# Phase 2: Check extracted endpoints
cat ./results/js_critical_info.json | jq '.endpoints[].url'

# Phase 3: Test each endpoint
api_hunter scan https://api.target.com/v1 --sV --sA -T3 --report bounty.txt
```

---

## 🎓 Tips & Tricks

### Tip 1: Always Start with Deep JS
```bash
api_hunter scan https://target.com --deep-js -T3
```
Reveals hidden endpoints, secrets, and parameters before vulnerability testing.

### Tip 2: Use Reports for Large Scans
```bash
api_hunter scan https://target.com --sV --report findings.txt
```
Keeps CLI clean while saving all details to file.

### Tip 3: Check XSS Findings Separately
```bash
cat ./results/xss_findings.json | jq '.[] | select(.severity == "High")'
```
Filter for high-severity exploitable XSS only.

### Tip 4: Monitor Scan Progress
```bash
# In another terminal
tail -f ./results/analysis_summary.txt
```
Watch results update in real-time.

### Tip 5: Batch Scan Multiple Targets
```bash
cat targets.txt | while read target; do
  api_hunter scan "$target" --sV -T3 --report "report_${target}.txt"
  sleep 60  # Delay between targets
done
```

---

## 📞 Support

For issues or questions:
1. Check `./results/analysis_summary.txt` for errors
2. Review `IMPROVEMENTS_COMPLETED.md` for known issues
3. Enable debug logging: `RUST_LOG=debug api_hunter scan ...`

---

**Version:** 0.1.0  
**Last Updated:** November 30, 2025  
**Build Status:** ✅ Compiled Successfully
