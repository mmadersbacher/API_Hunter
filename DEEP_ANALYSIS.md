# Deep Analysis Features  ## Overview
API_Hunter now includes comprehensive deep analysis capabilities for security testing and bug bounty hunting.  ## New Features  ### 1. **Security Header Analysis**
- Evaluates 6 critical security headers:  - HSTS (HTTP Strict Transport Security)  - Content-Security-Policy (CSP)  - X-Frame-Options (Clickjacking protection)  - X-Content-Type-Options (MIME sniffing)  - Referrer-Policy (Information leakage)  - Permissions-Policy (Feature restriction)
- Generates a security score (0-100) for each endpoint
- Identifies missing headers and security gaps  ### 2. **CORS Configuration Analysis**
- Detects CORS misconfigurations:  - Wildcard origins (`*`) allowing any domain  - Null origin acceptance  - Credential misconfigurations  - Dangerous HTTP methods (PUT, DELETE, PATCH)
- Classifies vulnerabilities by severity  ### 3. **Technology Fingerprinting**
- **CDN Detection**: Cloudflare, Fastly, Akamai, CloudFront, Azure CDN
- **Framework Detection**: Express.js, Next.js, React, Vue, Angular, WordPress, Drupal, Nuxt, ASP.NET, PHP
- **Language Detection**: PHP, C#/.NET, Python, JSP/Java
- **Database Hints**: MySQL, PostgreSQL, MongoDB
- Extracted from headers and response body patterns  ### 4. **Admin Endpoint Scanner**
- Tests 45+ common admin/debug paths:  - Admin panels: `/admin`, `/administrator`, `/control`, `/panel`  - Debug endpoints: `/debug`, `/internal`, `/test`  - API documentation: `/swagger`, `/graphql`, `/api-docs`  - Configuration: `/.env`, `/.git/config`, `/config.json`  - Monitoring: `/health`, `/status`, `/metrics`, `/actuator`
- Risk classification:  - 🔴 **Critical**: Publicly accessible admin interfaces  - 🟠 **High**: Accessible debug/internal endpoints  - 🟡 **Medium**: Exposed but requires authentication  - 🔵 **Low**: Not accessible (404/403)  ### 5. **Advanced IDOR Testing**
- Intelligent test value generation based on parameter type:  - **Numeric IDs**: Sequential (±1, ±10), common values (1, 2, 100, 999), negative, large numbers  - **UUIDs**: Zero UUID, all-ones UUID, modified segments  - **Hashes**: Repeated characters, zero-filled patterns  - **Strings**: Common usernames (admin, test, user, 1)
- Three-tier risk analysis:  - 🔴 **Critical**: Different data returned for modified ID (actual IDOR)  - 🟠 **High**: Status code changes to 200 OK  - 🟡 **Medium**: Suspicious response patterns  ### 6. **Comprehensive API Analysis**
- Full header inspection
- Response body preview (500 chars)
- Content-Type detection
- Authentication requirement detection
- OPTIONS method testing (allowed methods)
- Response time measurement
- Finding aggregation and categorization  ## Usage  ### Basic Deep Analysis
```bash
api_hunter scan https://target.com/ --deep-analysis
```  ### With Admin Scanning
```bash
api_hunter scan https://target.com/ --deep-analysis --scan-admin
```  ### Full Bug Bounty Mode
```bash
api_hunter scan https://target.com/ --deep-analysis --scan-admin --advanced-idor --timeout 120
```  ### Combined with Parameter Fuzzing
```bash
api_hunter scan https://target.com/ --deep-analysis --scan-admin --advanced-idor --fuzz-params --test-idor --timeout 180
```  ## Output Files  ### `analysis_results.json`
Complete JSON output containing:
```json
{  "analyses": [  {  "url": "https://api.example.com/endpoint",  "status": 200,  "security_analysis": {  "security_score": 35,  "missing_headers": ["HSTS", "CSP"],  "findings": ["X-Powered-By leaks technology"]  },  "cors_analysis": {  "is_misconfigured": true,  "vulnerabilities": ["Wildcard origin allows any domain"]  },  "technology": {  "framework": ["Express.js"],  "cdn": ["Cloudflare"]  },  "findings": ["PUBLIC: Endpoint accessible without auth"]  }  ],  "admin_findings": [  {  "url": "https://target.com/admin",  "status": 200,  "accessible": true,  "requires_auth": false,  "risk_level": "Critical"  }  ],  "idor_findings": [  {  "url": "https://api.example.com/users?id=123",  "parameter": "id",  "test_value": "124",  "is_vulnerable": true,  "risk_level": "Critical",  "evidence": "Different user data returned"  }  ]
}
```  ### `analysis_summary.txt`
Human-readable summary with:
- Security scores by endpoint
- CORS misconfigurations
- Technology fingerprints
- Admin endpoints found (with risk levels)
- IDOR vulnerabilities (with evidence)
- Overall statistics (Critical/High/Medium counts)  ## Example Results  ### Security Analysis
```
URL: https://api.example.com/v1/users
Status: 200
Security Score: 35/100
⚠️  LOW SECURITY SCORE
⚠️  CORS MISCONFIGURED  - PUBLIC: Endpoint is publicly accessible without authentication  - Missing HSTS - not enforcing HTTPS  - Missing CSP - vulnerable to XSS  - WARNING: Wildcard origin (*) allows any domain  - INFO: Dangerous method allowed: DELETE
Technology: Express.js, Cloudflare
```  ### Admin Endpoint Discovery
```
=== Admin/Debug Endpoints Found ===
🔴 https://target.com/admin - Status: 200 - Auth: Not Required
🔴 https://target.com/admin/dashboard - Status: 200 - Auth: Not Required
🔴 https://target.com/debug - Status: 200 - Auth: Not Required
🟠 https://target.com/internal - Status: 200 - Auth: Required
🟡 https://target.com/swagger - Status: 401 - Auth: Required
```  ### IDOR Vulnerability
```
=== IDOR Vulnerabilities ===
🔴 CRITICAL - https://api.example.com/users?id=123  Parameter: id (original: 123, test: 124)  Evidence: Different user data returned (size change: 1234 -> 1567 bytes)
```  ## Performance Considerations  - **Analysis Phase**: ~200ms delay between endpoint analyses
- **Admin Scanning**: ~5ms delay between path tests (45 paths × N domains)
- **IDOR Testing**: ~100-150ms delay between tests
- **Timeout**: Recommended 120-180s for comprehensive analysis
- **Incremental Saving**: Results written after each phase to prevent data loss  ## Best Practices  1. **Start with Discovery**: Run without analysis first to identify APIs
2. **Focused Scans**: Use specific subdomains (e.g., `admin.example.com`) for faster results
3. **Combine Features**: Use `--deep-analysis --scan-admin --advanced-idor` together
4. **Long Timeouts**: Set `--timeout 180` or higher for large targets
5. **Lite Mode**: Add `--lite` to reduce concurrency and avoid rate limiting
6. **Review JSON**: Parse `analysis_results.json` for programmatic analysis  ## CLI Flags  | Flag | Description | Default | |------|-------------|---------| | `--deep-analysis` | Enable comprehensive API analysis | `false` | | `--scan-admin` | Scan for admin/debug endpoints | `false` | | `--advanced-idor` | Advanced IDOR testing with multiple techniques | `false` | | `--fuzz-params` | Parameter fuzzing (from previous version) | `false` | | `--test-idor` | Basic IDOR testing (from previous version) | `false` | | `--timeout` | Total scan timeout in seconds | `10` | | `--lite` | Low-impact mode | `false` | ## Integration with Existing Features  Deep analysis works seamlessly with:
- **Discovery Phase**: Analyzes all discovered APIs
- **Probe Phase**: Runs after successful probes
- **Fuzzing Phase**: Can run before or after parameter fuzzing
- **Output System**: Writes to same `results/` directory  ## Real-World Results  Testing on `https://admin.pubnub.com/`:
- **107 APIs discovered**
- **44 Critical findings** (public admin endpoints)
- **48 High findings** (CORS, security headers)
- **262 Medium findings** (missing headers, info leaks)
- **Total: 354 security issues identified**  ## Future Enhancements  Potential additions:
- [ ] JWT token analysis
- [ ] GraphQL introspection testing
- [ ] Subdomain takeover detection
- [ ] Sensitive data extraction (emails, API keys)
- [ ] Rate limiting detection
- [ ] Authentication bypass testing
- [ ] File upload vulnerability testing
