# API Hunter - Professional CLI Design

## Design Philosophy

API Hunter follows the **nmap design philosophy**: clean, professional, information-dense output without distracting emojis or unnecessary decoration.

## Output Prefixes

We use consistent, professional prefixes for all output:

| Prefix | Meaning | Usage | Color (Terminal) |
|--------|---------|-------|------------------|
| `[*]` | Information/Status | General information, feature lists, progress | White/Cyan |
| `[+]` | Success/Found | Successful operations, discovered items | Green |
| `[-]` | Details/List Items | Sub-items, details, nested information | Gray |
| `[!]` | Warning/Error | Errors, warnings, critical messages | Red/Yellow |

## Output Structure

### 1. Scan Header
```
┌──────────────────────────────────────────────────┐
│            API Hunter v1.0 - Scan Engine         │
└──────────────────────────────────────────────────┘

[*] Target: example.com
[*] Mode: Standard

[*] Standard Features (Always Active):
    + WAF Detection (passive)
    + Security Headers Analysis
    + CORS Configuration Check
    + Technology Fingerprinting

[*] Advanced Features:
    + Vulnerability Scanning (SQLi, XSS, RCE, etc.)
    + Admin/Debug Endpoint Scanning

------------------------------------------------------------
```

### 2. Scan Progress
```
[*] Scanning endpoints...
[+] Found API: /api/v1/users
[+] Found API: /api/v1/posts
[-] Status: 200 OK
[-] WAF: Cloudflare detected
```

### 3. Scan Summary
```
============================================================
[*] Scan Summary
============================================================
[+] APIs Found: 42

[*] WAF Detections:
    [-] Cloudflare: 12 endpoint(s)
    [-] Akamai: 5 endpoint(s)

[*] Status Codes:
    [-] 200: 30 endpoint(s)
    [-] 404: 10 endpoint(s)
    [-] 403: 2 endpoint(s)

[*] Output Location: ./results
    [-] Parameter fuzzing: fuzz_results.txt
    [-] Deep analysis: analysis_summary.txt
============================================================
```

### 4. Error Messages
```
[!] ERROR: Aggressive mode requires explicit confirmation
[!] Add --confirm-aggressive flag
```

### 5. Warnings
```
[!] No residential proxy configured. Using direct connection.
[!] Set RESIDENTIAL_PROXY env: username:password@gate.provider.com:7000
```

## Design Principles

### 1. **No Emojis**
- Professional appearance
- Terminal compatibility
- Screen reader friendly
- No encoding issues

### 2. **Consistent Prefixes**
- Easy to parse (grep-friendly)
- Clear information hierarchy
- Scannable output

### 3. **Box Drawing**
- ASCII box characters for headers: `┌─┐│└┘`
- Simple separators: `===` and `---`
- Clean visual structure

### 4. **Information Density**
- Relevant information only
- No unnecessary decoration
- Clear hierarchy (prefix → indentation)

### 5. **Terminal Friendly**
- Works in all terminals
- Monospace-optimized
- Copy-paste friendly
- Scriptable output

## Inspiration

This design is inspired by industry-standard security tools:

- **nmap**: Clean, professional output with clear prefixes
- **masscan**: Minimal, fast, information-dense
- **sqlmap**: Professional scanning output
- **Metasploit**: Clear module output with status indicators

## Example Comparison

### ❌ OLD (with emojis)
```
🔍 API Hunter - Starting Scan
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ WAF Detection (passive)
🛡️  WAF Detections:
   • Cloudflare: 12 endpoint(s)
📈 Status Codes:
   • 200: 45 endpoint(s)
📁 Output Location: ./results
```

### ✅ NEW (professional)
```
┌──────────────────────────────────────────────────┐
│            API Hunter v1.0 - Scan Engine         │
└──────────────────────────────────────────────────┘
[*] Standard Features (Always Active):
    + WAF Detection (passive)

[*] WAF Detections:
    [-] Cloudflare: 12 endpoint(s)

[*] Status Codes:
    [-] 200: 45 endpoint(s)

[*] Output Location: ./results
```

## Benefits

1. **Professional Appearance**: Suitable for security reports and presentations
2. **Terminal Compatibility**: Works everywhere (Windows, Linux, macOS)
3. **Parsing Friendly**: Easy to grep, awk, sed
4. **Accessibility**: Screen reader friendly
5. **Encoding Safe**: No UTF-8 emoji issues
6. **Industry Standard**: Follows established security tool conventions

## Usage in Scripts

The new design is perfect for automation:

```bash
# Extract all found APIs
api_hunter scan target.com | grep "^\[+\] Found API"

# Extract errors only
api_hunter scan target.com | grep "^\[!\]"

# Extract WAF detections
api_hunter scan target.com | grep -A 10 "WAF Detections"
```

## Color Coding (Optional)

While the tool primarily uses monochrome output, color support is available for interactive terminals:

- `[*]` → Cyan (information)
- `[+]` → Green (success)
- `[-]` → White/Gray (details)
- `[!]` → Red/Yellow (errors/warnings)

Colors are automatically disabled when output is piped or redirected.

---

**Version**: 2.0  
**Last Updated**: November 2025  
**Status**: Production Ready
