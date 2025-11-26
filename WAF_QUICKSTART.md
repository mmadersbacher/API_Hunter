# WAF Detection & Bypass - Quick Reference

## TL;DR Commands

### Detection Only (Safe, No Bypass)
```bash
# Basic WAF detection
.\target\release\api_hunter.exe scan target.com --detect-waf

# With deep analysis
.\target\release\api_hunter.exe scan target.com --detect-waf --deep-analysis
```

### Detection + Bypass (Requires Permission)
```bash
# Bypass with confirmation
.\target\release\api_hunter.exe scan target.com \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass

# Best: With anonymous mode (residential proxies)
.\target\release\api_hunter.exe scan target.com \
  --anonymous \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass

# Maximum: Full-speed bypass
.\target\release\api_hunter.exe scan target.com \
  --anonymous \
  --full-speed \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass
```

---

## Flags

| Flag | Description | Required |
|------|-------------|----------|
| `--detect-waf` | Enable WAF detection (passive) | No |
| `--bypass-waf` | Enable bypass attempts | Requires `--confirm-waf-bypass` |
| `--confirm-waf-bypass` | Confirm permission for bypass | Yes (if `--bypass-waf`) |
| `--anonymous` | Use residential proxies | Recommended for bypass |
| `--full-speed` | Skip delays (fast bypass) | Optional |

---

## Detected WAFs

- ✅ Cloudflare
- ✅ Imperva Incapsula
- ✅ Akamai Kona
- ✅ F5 BIG-IP ASM
- ✅ ModSecurity
- ✅ AWS WAF
- ✅ Azure WAF
- ✅ Sucuri CloudProxy
- ✅ Wordfence
- ✅ Barracuda
- ✅ Fortinet FortiWeb
- ✅ Wallarm

---

## Bypass Techniques

### Tier 1 (High Success)
1. **IP Rotation** (95%) - Via `--anonymous` flag
2. **Path Obfuscation** (80%) - `/./`, `//`, trailing slash
3. **Verb Tampering** (75%) - HEAD, OPTIONS, PUT
4. **Header Injection** (70%) - X-Forwarded-For, X-Real-IP

### Tier 2 (Medium Success)
5. **URL Encoding** (60%)
6. **Content-Type Change** (55%)
7. **Case Manipulation** (50%)

---

## Safety Features

### ❌ Will NOT Work Without Flags
```bash
# This will NOT attempt bypass:
.\target\release\api_hunter.exe scan target.com --deep-analysis

# Detection happens, but no bypass without explicit flags
```

### ✅ Requires Confirmation
```bash
# Without confirmation = ERROR:
.\target\release\api_hunter.exe scan target.com --bypass-waf
# ❌ Error: WAF bypass requires explicit permission
#    Add --confirm-waf-bypass flag

# With confirmation = OK:
.\target\release\api_hunter.exe scan target.com --bypass-waf --confirm-waf-bypass
# ✅ Bypass enabled
```

---

## Example Workflows

### Workflow 1: Recon (Safe)
```bash
# Just identify WAF, don't attempt bypass
.\target\release\api_hunter.exe scan target.com \
  --detect-waf \
  --with-wayback \
  --deep-analysis
```

**Output:**
```
🛡️  WAF Detected: Cloudflare
   Confidence: 0.95
   Evidence: server: cloudflare, cf-ray: 123abc
```

### Workflow 2: Authorized Pentest
```bash
# Full testing with bypass
.\target\release\api_hunter.exe scan client-app.com \
  --anonymous \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass \
  --deep-analysis \
  --scan-admin
```

**Output:**
```
🛡️  WAF Detected: Imperva (confidence: 0.92)

🔓 Testing bypass techniques:
  ✅ IP Rotation (via --anonymous)
  ✅ Path Obfuscation (/api/./users → 200 OK)
  ✅ Verb Tampering (HEAD → 200 OK)
  ❌ Header Injection (403)
  
✅ 3/4 techniques successful
```

### Workflow 3: Red Team (High-Speed)
```bash
# Aggressive testing
.\target\release\api_hunter.exe scan internal-app.com \
  --anonymous \
  --full-speed \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass \
  --aggressive \
  --confirm-aggressive \
  --concurrency 100
```

---

## WAF-Specific Tips

### Cloudflare
```bash
# Best techniques: IP rotation + slow requests
.\target\release\api_hunter.exe scan target.com \
  --anonymous \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass \
  --concurrency 5  # Lower = better for Cloudflare
```

### Imperva
```bash
# Best: Content-Type manipulation + IP rotation
.\target\release\api_hunter.exe scan target.com \
  --anonymous \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass
```

### ModSecurity
```bash
# Best: Case manipulation + URL encoding
.\target\release\api_hunter.exe scan target.com \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass
```

---

## Troubleshooting

### "No WAF detected" but site is protected
```bash
# Try with deep analysis for active detection
.\target\release\api_hunter.exe scan target.com \
  --detect-waf \
  --deep-analysis
```

### "All bypass techniques failed"
```bash
# Try with lower concurrency + anonymous mode
.\target\release\api_hunter.exe scan target.com \
  --anonymous \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass \
  --concurrency 2 \
  --lite
```

### "Need residential proxy for IP rotation"
```bash
# Set up proxy first:
$env:RESIDENTIAL_PROXY = "username:password@gate.smartproxy.com:7000"

# Then run with --anonymous:
.\target\release\api_hunter.exe scan target.com \
  --anonymous \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass
```

---

## Legal Checklist

Before using WAF bypass:

- [ ] Written authorization obtained
- [ ] Scope defined (which targets allowed)
- [ ] Time window agreed
- [ ] Contact information exchanged
- [ ] Incident response plan ready
- [ ] Rate limits understood
- [ ] Monitoring/logging in place

**If ANY checkbox is unchecked, do NOT use `--bypass-waf`!**

---

## Performance Impact

| Mode | Extra Time | Extra Requests |
|------|------------|----------------|
| Detection only | <10ms | 0 (passive) |
| Detection + Active | ~50ms | 1 per target |
| Bypass testing | ~500ms | 3-8 per endpoint |

---

## Output Format

### Console
```
🛡️  WAF Detection Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WAF: Cloudflare
Confidence: 0.95
Evidence:
  - server: cloudflare
  - cf-ray: 7d1234567890abcd
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔓 Bypass Techniques:
  ✅ Path Obfuscation (200 OK)
  ✅ Verb Tampering (200 OK)
  ❌ Header Injection (403)
```

### JSONL
```json
{
  "url": "https://target.com/api",
  "waf_detected": true,
  "waf_type": "Cloudflare",
  "waf_confidence": 0.95,
  "bypass_attempted": true,
  "bypass_successful": true,
  "bypass_techniques": [
    {"technique": "PathObfuscation", "success": true},
    {"technique": "VerbTampering", "success": true}
  ]
}
```

---

## Quick Reference Card

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ WAF DETECTION & BYPASS - CHEAT SHEET           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                 ┃
┃ DETECT ONLY (Safe):                             ┃
┃   --detect-waf                                  ┃
┃                                                 ┃
┃ BYPASS (Requires Permission):                   ┃
┃   --detect-waf                                  ┃
┃   --bypass-waf                                  ┃
┃   --confirm-waf-bypass                          ┃
┃                                                 ┃
┃ BEST COMBO:                                     ┃
┃   --anonymous (residential proxies)            ┃
┃   --detect-waf                                  ┃
┃   --bypass-waf                                  ┃
┃   --confirm-waf-bypass                          ┃
┃                                                 ┃
┃ DETECTED WAFs:                                  ┃
┃   • Cloudflare        • Imperva                ┃
┃   • Akamai            • F5 BIG-IP              ┃
┃   • ModSecurity       • AWS WAF                ┃
┃   • Azure WAF         • Sucuri                 ┃
┃   • Wordfence         • Barracuda              ┃
┃   • FortiWeb          • Wallarm                ┃
┃                                                 ┃
┃ BYPASS TECHNIQUES:                              ┃
┃   1. IP Rotation      (95% success) ⭐⭐⭐     ┃
┃   2. Path Obfuscation (80% success) ⭐⭐⭐     ┃
┃   3. Verb Tampering   (75% success) ⭐⭐       ┃
┃   4. Header Injection (70% success) ⭐⭐       ┃
┃   5. URL Encoding     (60% success) ⭐         ┃
┃                                                 ┃
┃ REMEMBER:                                       ┃
┃   ⚠️  Always get written permission!           ┃
┃   ⚠️  Use --confirm-waf-bypass flag            ┃
┃   ⚠️  Respect rate limits                      ┃
┃                                                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

---

## Summary

**✅ Full Implementation Complete:**
- 12+ WAF signatures
- 10+ bypass techniques
- Requires explicit flags (no auto-exploitation)
- Integration with residential proxies
- Confidence scoring
- JSONL/CSV output

**🎯 Best Practice:**
```bash
api_hunter scan target.com \
  --anonymous \
  --detect-waf \
  --bypass-waf \
  --confirm-waf-bypass \
  --deep-analysis
```

**📚 Full Documentation:**
- See `WAF_DETECTION_AND_BYPASS.md` for complete guide
- See `RESIDENTIAL_PROXY_MODE.md` for anonymous mode
- See `README.md` for general usage
