# Deep JavaScript Analysis

## Overview

The **Deep JavaScript Analysis** feature mimics what bug bounty hunters manually do when inspecting JavaScript files in browser DevTools (F12 Network tab). It automatically discovers, downloads, and thoroughly analyzes all JavaScript files to extract critical security information.

## What It Extracts

### 🎯 API Endpoints
- **fetch()** calls with HTTP methods
- **axios** requests (GET, POST, PUT, DELETE, PATCH)
- **XMLHttpRequest** operations
- **jQuery AJAX** calls
- URL constructors and API path definitions
- Includes HTTP method and surrounding code context

### 🔑 Secrets & Tokens
- **API Keys** (various patterns)
- **Bearer Tokens** 
- **JWT Tokens** (eyJ... format)
- **AWS Access Keys** (AKIA...)
- **Private Keys** (PEM format)
- **Client Secrets**
- **Webhook URLs** (Slack, Discord)
- **Database Connection Strings** (MongoDB, PostgreSQL, MySQL)
- Filters out test/example values automatically

### 🌐 Domains & Subdomains
- External API domains
- CDN endpoints
- Subdomain references
- Third-party service URLs

### 📋 Parameters
- **Query parameters** (?param=value)
- **Path parameters** ({id}, :id, ${id})
- **Body parameters**
- **Header parameters**
- Includes example values when available

### 🔌 WebSocket Endpoints
- ws:// and wss:// URLs
- WebSocket constructor calls

### 📊 GraphQL Information
- GraphQL endpoint URLs
- Query operation names
- Mutation operation names
- Full operation extraction

### 📁 Cloud Storage
- **AWS S3** buckets
- **Google Cloud Storage** buckets
- **Azure Blob Storage** URLs
- **Cloudflare R2** endpoints

### 📧 Contact Information
- Email addresses (filtered for real emails)

### 💬 Debug Comments
- TODO, FIXME, HACK, BUG comments
- Debug information
- Sensitive keywords in comments (API, TOKEN, KEY, SECRET)

### 🔗 Third-Party Integrations
- Stripe (API keys)
- PayPal (client IDs)
- Twilio (account SIDs)
- SendGrid (API keys)
- Google APIs (API keys)
- Firebase (config)
- Google Analytics (tracking IDs)
- Sentry (DSN)
- Intercom (app IDs)
- Segment (write keys)

### 🗺️ Source Maps
- .map file URLs for debugging

### 📦 Version Information
- Application versions
- Framework versions (React, Vue, Angular, Next.js)

## Usage

### Basic Usage

```powershell
# Enable deep JS analysis
cargo run --release -- scan https://target.com --deep-js

# Combine with other features
cargo run --release -- scan https://target.com --deep-js --deep --scan-admin
```

### Anonymous Scanning

```powershell
# Deep JS analysis with anonymous mode
cargo run --release -- scan https://target.com --deep-js --anonymous --lite
```

### High-Speed Analysis

```powershell
# Maximum speed with high concurrency
cargo run --release -- scan https://target.com --deep-js -T5 -c 200
```

## Output

### Console Output

```
[*] Deep JS Analysis: Scanning all JavaScript files for critical information...
    [+] Endpoints: 47
    [+] Secrets/Tokens: 3 ⚠️
    [+] Parameters: 89
    [+] Domains: 12
    [+] WebSockets: 2
    [+] GraphQL: 1
    [+] Cloud Storage: 5
    [+] Integrations: 7
    [+] Critical info saved to: results/js_critical_info.json

    ⚠️  WARNING: Found 3 potential secrets/tokens in JavaScript files!
    Check results/js_critical_info.json for details

    📦 Found 5 cloud storage URLs (S3/GCS/Azure)
```

### JSON Output File

All findings are saved to `results/js_critical_info.json`:

```json
{
  "endpoints": [
    {
      "url": "/api/v1/users",
      "method": "GET",
      "source_file": "https://target.com/static/js/main.js",
      "context": "axios.get('/api/v1/users', { headers: { 'Authorization': ..."
    }
  ],
  "secrets": [
    {
      "secret_type": "ApiKey",
      "value": "sk_live_51H...",
      "source_file": "https://target.com/js/checkout.js",
      "line_context": "const stripeKey = 'sk_live_51H...'"
    }
  ],
  "parameters": [
    {
      "name": "userId",
      "param_type": "Path",
      "example_value": null,
      "source_file": "https://target.com/app.js"
    }
  ],
  "domains": ["api.example.com", "cdn.example.com"],
  "websockets": ["wss://live.example.com/socket"],
  "graphql": [
    {
      "endpoint": "/graphql",
      "queries": ["GetUser", "ListPosts"],
      "mutations": ["CreatePost", "UpdateUser"],
      "source_file": "https://target.com/graphql.js"
    }
  ],
  "cloud_storage": [
    {
      "storage_type": "S3",
      "bucket_url": "https://mybucket.s3.amazonaws.com/uploads/",
      "source_file": "https://target.com/uploader.js"
    }
  ],
  "integrations": [
    {
      "service": "Stripe",
      "identifier": "pk_live_...",
      "source_file": "https://target.com/checkout.js"
    }
  ],
  "versions": {
    "app_version": "2.4.1",
    "react": "18.2.0"
  }
}
```

## Performance

### Optimization Features

1. **Concurrent Analysis**: Analyzes multiple JS files simultaneously
2. **Size Limits**: 
   - Max 2MB per JavaScript file
   - Prevents memory exhaustion
3. **Smart Discovery**: 
   - Parses HTML for `<script src="">` tags
   - Extracts JS references from inline scripts
   - Checks common JS paths
4. **Timeout Protection**: 60-second timeout prevents hanging
5. **Deduplication**: Automatic deduplication of all findings

### Timing Recommendations

| Scan Type | Timing Template | Concurrency | Use Case |
|-----------|----------------|-------------|----------|
| Stealth | T0-T1 | 1-5 | Maximum stealth, slow |
| Standard | T2-T3 | 15-50 | Bug bounty reconnaissance |
| Fast | T4 | 100 | Authorized testing |
| Maximum | T5 | 200 | Internal security audits |

## Real-World Examples

### Bug Bounty Hunting

```powershell
# Stealthy recon with full JS analysis
cargo run --release -- scan target.hackerone.com \
  --deep-js \
  --anonymous \
  --lite \
  -T2
```

### Red Team Assessment

```powershell
# Comprehensive analysis with all features
cargo run --release -- scan internal.target.com \
  --deep-js \
  --deep \
  --scan-admin \
  --scan-vulns \
  -T3
```

### Pentesting Engagement

```powershell
# Maximum speed for authorized testing
cargo run --release -- scan client.com \
  --deep-js \
  --deep \
  --aggressive \
  -T5 \
  -c 200
```

## What Gets Tested After Discovery

Endpoints discovered by Deep JS Analysis are automatically:

1. ✅ Added to the active probing queue
2. ✅ Tested for HTTP methods
3. ✅ Checked for authentication requirements
4. ✅ Analyzed for security headers
5. ✅ Scanned for vulnerabilities (if `--scan-vulns`)
6. ✅ Tested for IDOR (if `--advanced-idor`)
7. ✅ Parameter fuzzed (if `--fuzz-params`)

## Security Considerations

### ⚠️ Secrets Detection

When secrets are found:
- Immediately saved to `js_critical_info.json`
- Warning displayed in console
- Recommended to check immediately
- **Never commit this file to git**

### 🔒 Responsible Disclosure

If you find secrets in JavaScript files:
1. **Do not exploit** the secrets
2. **Report immediately** to the security team
3. Document in your report
4. Follow responsible disclosure guidelines

### 📝 Legal Notice

- Only scan applications you have permission to test
- Respect bug bounty program scope
- Some programs may not allow automated scanning
- Always check the program rules first

## Advanced Filtering

### Automatic Filters Applied

**URLs Excluded:**
- Image files (.jpg, .png, .gif, .svg)
- CSS files
- Font files (.woff, .ttf)
- Data URIs (data:, blob:)

**Secrets Excluded:**
- Test/example values
- Common placeholders (xxx, test, demo)
- Obviously fake keys

**Emails Excluded:**
- example.com addresses
- test.com addresses

## Comparison with Manual Analysis

| Task | Manual F12 | Deep JS Analysis |
|------|-----------|------------------|
| Find JS files | 5-10 min | Instant |
| Extract endpoints | 10-30 min | Instant |
| Find API keys | 15-45 min | Instant |
| Extract parameters | 20-60 min | Instant |
| Check integrations | 10-20 min | Instant |
| Find cloud storage | Variable | Instant |
| **Total Time** | **60-165 min** | **< 1 min** |

## Integration with Other Features

### Works Great With:

- `--deep`: Combines with Wayback/GAU for historical data
- `--browser`: Browser-based discovery + deep JS analysis
- `--anonymous`: Stealth mode for sensitive targets
- `--scan-vulns`: Found endpoints are automatically tested
- `--scan-admin`: Discovered admin endpoints are verified
- `--fuzz-params`: Parameters are automatically fuzzed

### Workflow Example:

```powershell
# Phase 1: Anonymous reconnaissance with JS analysis
cargo run --release -- scan target.com --deep-js --anonymous --lite

# Phase 2: Review js_critical_info.json for sensitive findings

# Phase 3: Deep testing on discovered endpoints
cargo run --release -- scan target.com --deep --scan-vulns --scan-admin
```

## Troubleshooting

### "Deep JS analysis failed"

**Possible causes:**
- Target has no JavaScript files
- JavaScript files are behind authentication
- Network timeout issues

**Solutions:**
- Check if target uses JavaScript frameworks
- Increase timeout: `--timeout 30`
- Try with authentication headers (if authorized)

### "Deep JS analysis timed out"

**Solution:**
- Reduce concurrency: `-c 20`
- Use faster timing template: `-T4`
- Check network connectivity

### No secrets found

**This is usually good!** It means:
- No exposed secrets in client-side code
- Good security practices by developers
- Secrets are properly managed server-side

## Best Practices

### 1. Always Review JSON Output

The console output is a summary. Always check `js_critical_info.json` for:
- Full context of each finding
- Source file locations
- Example values for parameters

### 2. Prioritize Secret Findings

If secrets are found:
1. Stop further testing
2. Report immediately
3. Document thoroughly
4. Don't use the secrets

### 3. Cross-Reference Domains

Discovered domains may lead to:
- Additional targets in scope
- Internal APIs
- Third-party integrations
- Development/staging environments

### 4. Test Discovered Endpoints

Don't just collect endpoints - test them:
```powershell
# Discover endpoints
cargo run --release -- scan target.com --deep-js

# Review findings in js_critical_info.json

# Test discovered endpoints
cargo run --release -- test-endpoint <discovered-url> --fuzz
```

## Future Enhancements

Planned features:
- [ ] Source map downloading and analysis
- [ ] Webpack/Babel deobfuscation
- [ ] Pattern-based secret scoring
- [ ] Integration with external secret scanning tools
- [ ] Historical comparison (detect new secrets)
- [ ] Export to nuclei templates

## Credits

Inspired by manual bug bounty hunting techniques and tools like:
- LinkFinder
- JSParser
- GetJS
- Burp Suite's JS analysis
- Manual DevTools inspection workflows
