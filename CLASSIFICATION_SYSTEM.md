# Vulnerability Classification System  ## Overview
This document describes the **STRICT** risk classification system used in API_Hunter. The system is designed to minimize false positives and ensure that Critical findings represent **EXPLOITABLE** vulnerabilities.  ## Classification Levels  ### 🔴 Critical (CVSS 9.0-10.0) **Definition**: Confirmed exploitable vulnerabilities that allow immediate system compromise, data breach, or account takeover. **Criteria** (ALL must be met):
1. Vulnerability is **confirmed** through actual exploit attempt
2. Impact is **immediate and severe** (RCE, SQLi with data extraction, Auth Bypass)
3. Exploit requires **no special privileges** or minimal interaction
4. Can lead to **full system compromise** or **sensitive data exposure** **Examples**:
- **SQL Injection**: Database error messages with successful payload  - Score: 9.8  - Evidence: SQL syntax errors, mysql_fetch errors, data extraction  - Test: Multiple payloads (`'`, `' OR '1'='1`, `UNION SELECT`)  - **Remote Command Execution**: System command output in response  - Score: 9.8  - Evidence: `uid=`, `gid=`, directory listings, file contents  - Test: Command injection payloads (`;`, `|`, `` ` ``, `$()`)  - **Authentication Bypass**: Unauthorized access with broken/missing token  - Score: 9.1  - Evidence: 200 OK with invalid token, admin access without auth  - Test: Null tokens, invalid signatures, header manipulation  - **Path Traversal + File Read**: Arbitrary file access confirmed  - Score: 8.6  - Evidence: `/etc/passwd`, `win.ini` contents in response  - Test: `../../../etc/passwd`, encoded variations  - **CORS + Credentials + Wildcard**: Account takeover vector  - Score: 9.5  - Evidence: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`  - Impact: Any domain can access with user's credentials  - **IDOR with Different User Data**: Confirmed unauthorized data access  - Score: 9.8  - Evidence: Different user ID in response, sensitive data from another account  - Test: Sequential IDs, modified UUIDs returning 200 with different data  - **Public Admin Panel with State-Changing Operations**:  - Score: 9.5  - Evidence: `/admin`, `/dashboard` accessible without auth, can perform admin actions  - Test: Public access + POST/PUT/DELETE capabilities  ---  ### 🟠 High (CVSS 7.0-8.9) **Definition**: Likely exploitable vulnerabilities with significant impact but requiring some conditions or having limited scope. **Criteria**:
1. Vulnerability is **highly likely** but not 100% confirmed
2. Impact is **significant** but not complete system compromise
3. May require **some user interaction** or **specific conditions**
4. **Data exposure** or **partial access control bypass** **Examples**:
- **SSRF (Server-Side Request Forgery)**: Internal network access  - Score: 8.5  - Evidence: AWS metadata accessible, internal IPs reachable  - Test: `http://169.254.169.254/latest/meta-data/`, localhost access  - **IDOR with Unauthorized Access**: Status change to 200 + data returned  - Score: 7.5  - Evidence: Modified ID returns 200 where original didn't, response size >100 bytes  - Test: ID manipulation resulting in successful access  - **Public Debug Endpoints with Data**: Internal information exposed  - Score: 7.5  - Evidence: `/debug`, `/internal` accessible, response >500 bytes  - Test: Admin path scanner finding exposed endpoints  - **CORS Null Origin + Sensitive Operations**:  - Score: 7.5  - Evidence: Null origin accepted on state-changing endpoints  - Impact: Sandbox iframe bypass  - **Missing HSTS + Sensitive Data + Public Access**:  - Score: 7.0  - Combined factors: No HTTPS enforcement on sensitive endpoints  - Evidence: Security score <30, handles passwords/tokens, no transport security  ---  ### 🟡 Medium (CVSS 4.0-6.9) **Definition**: Potential security issues requiring further investigation or having limited exploitability. **Criteria**:
1. Vulnerability is **possible** but needs validation
2. Impact is **moderate** (information disclosure, limited access)
3. Requires **significant user interaction** or **specific conditions**
4. **Secondary security issues** that increase attack surface **Examples**:
- **XSS (Cross-Site Scripting)**: Reflected payload without encoding  - Score: 6.1  - Evidence: `<script>` tag reflected in HTML without escaping  - Test: Multiple XSS payloads, check if encoded in response  - **IDOR with Response Differences**: Suspicious changes observed  - Score: 5.5-6.5  - Evidence: Large response size difference (>500 bytes) OR status code change  - Test: ID manipulation with observable differences  - **CORS Wildcard Origin (no credentials)**:  - Score: 4.0  - Evidence: `Access-Control-Allow-Origin: *` without credentials  - Impact: Limited - can't access authenticated data  - **Missing Security Headers + Public Access**:  - Score: 5.0-6.0  - Evidence: Multiple missing headers (CSP, X-Frame-Options) on public endpoint  - Impact: Increases XSS/clickjacking risk  - **Admin Endpoints Exposed but Protected**:  - Score: 4.0  - Evidence: Admin path returns 200 but requires authentication  - Impact: Endpoint enumeration, potential brute force target  - **Dangerous HTTP Methods Allowed**:  - Score: 4.5  - Evidence: OPTIONS shows PUT/DELETE/PATCH allowed  - Impact: Depends on authentication and CSRF protection  ---  ### 🔵 Low (CVSS 0.1-3.9) **Definition**: Minor security concerns with minimal direct impact. **Criteria**:
1. Issue has **minimal security impact**
2. **Information disclosure** of non-sensitive data
3. **Best practice violations** without direct exploitability
4. **Defense-in-depth** issues **Examples**:
- **Single Missing Security Header**:  - Score: 1.0-2.0  - Evidence: One header missing (e.g., X-Content-Type-Options)  - Impact: Minimal alone, part of defense-in-depth  - **Technology Version Disclosure**:  - Score: 1.5  - Evidence: `X-Powered-By: Express`, `Server: nginx/1.18.0`  - Impact: Information gathering for targeted attacks  - **IDOR with Minor Differences**:  - Score: 3.0  - Evidence: Status code change but no data access  - Impact: Endpoint behavior enumeration  - **Admin Path Exists but Not Accessible**:  - Score: 2.0  - Evidence: `/admin` returns 403/401  - Impact: Confirms admin interface exists (enumeration)  - **Missing Referrer-Policy Alone**:  - Score: 1.0  - Evidence: No Referrer-Policy header  - Impact: Minor information leakage in referer header  ---  ### ℹ️ Info (CVSS 0.0) **Definition**: Informational findings with no direct security impact. **Criteria**:
1. **No security impact**
2. **Informational only** (technology fingerprinting, endpoint enumeration)
3. **Reconnaissance data** for further testing **Examples**:
- **Technology Fingerprinting**:  - Score: 0.0  - Evidence: Framework detected (React, Next.js, Express)  - Impact: None - just information gathering  - **CDN Detection**:  - Score: 0.0  - Evidence: Cloudflare, Fastly headers  - Impact: Infrastructure knowledge  - **Endpoint Enumeration**:  - Score: 0.0  - Evidence: API endpoints discovered  - Impact: Attack surface mapping  ---  ## Scoring Weights  ### Security Headers
| Header | Weight | Reason | |--------|--------|--------| | HSTS | 1.5 | Prevents downgrade attacks | | CSP | 2.0 | Primary XSS defense | | X-Frame-Options | 1.5 | Clickjacking protection | | X-Content-Type | 1.0 | MIME sniffing prevention | | Referrer-Policy | 1.0 | Privacy protection | | Permissions-Policy | 1.0 | Feature restriction | **Amplifiers**:
- +1.0 if public access
- +2.0 if sensitive data (passwords, tokens, PII)
- +1.5 if state-changing operations  ### CORS Issues
| Issue | Weight | Reason | |-------|--------|--------| | Wildcard + Credentials | 9.5 | **CRITICAL**: Account takeover | | Null Origin + Sensitive Ops | 5.0 | Sandbox bypass possible | | Wildcard Alone | 4.0 | Limited impact without credentials | | Dangerous Methods | +2.0 | Increases attack surface | ### IDOR
| Factor | Weight | Reason | |--------|--------|--------| | Different User Data | 9.8 | **CRITICAL**: Confirmed data access | | Unauthorized 200 + Data | 5.0 | Likely exploitable | | Large Size Difference | 4.0 | Suspicious behavior | | Status Change | 3.0 | Observable difference | | Minor Difference | 1.0 | Requires investigation | **Required Evidence**:
- Response size difference >50 bytes
- User data indicators (email, name, ID)
- JSON field comparison  ### Admin Endpoints
| Factor | Weight | Reason | |--------|--------|--------| | Public + No Auth + Sensitive | 6.0 | **CRITICAL**: Admin takeover | | Has State-Changing Ops | 3.5 | Can perform admin actions | | Debug Endpoint + Data | 5.0 | Information disclosure | | Public + No Auth | 4.0 | Access control issue | | Requires Auth | 2.0 | Properly secured | ---  ## Test Methodology  ### SQL Injection
```rust
Payloads tested: [  "'", "\"",  "' OR '1'='1", "\" OR \"1\"=\"1",  "' OR '1'='1' --", "admin'--",  "1' AND 1=1--",  "' UNION SELECT NULL--",  "1' ORDER BY 1--",
]  Indicators:
- "SQL syntax" in response
- "mysql_fetch", "ORA-", "PostgreSQL"
- "SQLite", "sqlite3.OperationalError"
- Response size difference >500 bytes
```  ### Command Injection
```rust
Payloads tested: [  "; ls", "| whoami", "`id`",  "$(whoami)", "&& dir",  "; cat /etc/passwd",
]  Indicators:
- "uid=", "gid=" in response
- "root:x:0:0" (passwd file)
- "Directory of" (Windows)
- "bin", "etc", "usr" (Unix paths)
```  ### Auth Bypass
```rust
Tests:
1. No authentication header
2. Invalid Bearer token
3. Null/undefined tokens
4. Path traversal in token
5. Cookie manipulation (admin=true)  Success criteria:
- 200 OK with invalid/missing token
- Access to restricted resources
```  ### Path Traversal
```rust
Payloads tested: [  "../../../etc/passwd",  "..\\..\\..\\windows\\win.ini",  "....//....//....//etc/passwd",  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]  Success criteria:
- "root:x:0:0" in response
- "[extensions]" (win.ini)
- Actual file contents
```  ### SSRF
```rust
Payloads tested: [  "http://127.0.0.1",  "http://localhost",  "http://169.254.169.254/latest/meta-data/",  "http://metadata.google.internal/computeMetadata/v1/",
]  Success criteria:
- "ami-id", "instance-id" (AWS)
- "computeMetadata" (GCP)
- Internal service responses
```  ---  ## Decision Matrix  ### Is it Critical?
```
✅ YES if:
- [ ] Confirmed exploit (actual RCE/SQLi/Auth Bypass)
- [ ] Direct data exposure (PII, credentials, sensitive business data)
- [ ] Account takeover possible (CORS wildcard + credentials)
- [ ] No authentication required
- [ ] CVSS 9.0-10.0  ❌ NO if:
- Missing security headers alone
- Technology disclosure
- Potential but unconfirmed vulnerability
- Requires significant user interaction
- No sensitive data involved
```  ### Is it High?
```
✅ YES if:
- [ ] Likely exploitable (SSRF, IDOR with evidence)
- [ ] Significant data exposure (non-critical but sensitive)
- [ ] Partial access control bypass
- [ ] CVSS 7.0-8.9  ❌ NO if:
- Cannot confirm exploitability
- Impact is minimal
- Just information disclosure
```  ### Is it Medium?
```
✅ YES if:
- [ ] Possible vulnerability (XSS, CSRF)
- [ ] Limited information disclosure
- [ ] Combined low-severity issues
- [ ] CVSS 4.0-6.9  ❌ NO if:
- Single missing header
- No observable impact
- Just best practice violation
```  ---  ## Examples from Real Scans  ### Example 1: Public Admin Panel
```
URL: https://admin.example.com/admin/dashboard
Status: 200 OK
Auth Required: NO
Response Size: 15,234 bytes
Contains: User management, system settings
Methods Allowed: GET, POST, PUT, DELETE  Classification: 🔴 CRITICAL (Score: 9.5)
Reason: Public admin panel without authentication + state-changing operations
Evidence: Can access admin functions without login
```  ### Example 2: CORS Wildcard Only
```
URL: https://api.example.com/public/stats
Status: 200 OK
CORS: Access-Control-Allow-Origin: *
Credentials: false
Response: {"total_users": 1000, "requests": 5000}  Classification: 🟡 MEDIUM (Score: 4.0)
Reason: CORS wildcard on public non-sensitive data, no credentials
Evidence: No authentication involved, public statistics
```  ### Example 3: Missing CSP Header
```
URL: https://blog.example.com/post/123
Status: 200 OK
Content-Type: text/html
Missing: Content-Security-Policy
Contains: Blog post (no user input reflection)  Classification: 🔵 LOW (Score: 2.0)
Reason: Missing CSP alone on static content
Evidence: No XSS vector, just missing defense-in-depth
```  ### Example 4: SQL Injection
```
URL: https://api.example.com/search?q='
Status: 500
Response: "mysql_fetch_array() expects parameter 1 to be resource, boolean given"  Classification: 🔴 CRITICAL (Score: 9.8)
Reason: Confirmed SQL injection via error message
Evidence: Database error with SQL payload, exploitable
```  ---  ## Summary **Critical Findings Should Be Rare!**
- On a well-secured website: 0-2 Critical findings expected
- On an average website: 3-10 Critical findings
- On a poorly secured website: 10+ Critical findings **Most Findings Will Be Low/Info!**
- Missing headers: Low
- Technology disclosure: Info
- Endpoint enumeration: Info
- Single security issues: Low
- Combined issues: Medium
- Confirmed exploits: High/Critical **Classification is Evidence-Based:**
- Critical: Confirmed with actual exploit
- High: Strong evidence of exploitability
- Medium: Observable security issues
- Low: Minor concerns
- Info: Reconnaissance only  This ensures that when you see **🔴 Critical**, it means **IMMEDIATE ACTION REQUIRED** - not just "missing a header".
