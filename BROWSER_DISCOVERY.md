# Browser-Based API Discovery

## Overview

API Hunter now includes **headless browser discovery** to find APIs that are only visible when JavaScript executes. This is crucial for modern Single Page Applications (SPAs) built with React, Vue, Angular, etc.

## Why Browser Discovery?

### Traditional Discovery (Static)
- ❌ Only finds URLs in HTML source code
- ❌ Misses dynamically loaded APIs
- ❌ Can't see authenticated endpoints
- ❌ No interaction with the page

### Browser Discovery (Dynamic)  
- ✅ Executes JavaScript like a real browser
- ✅ Captures XHR/Fetch requests
- ✅ Triggers lazy-loaded content
- ✅ Simulates user interactions
- ✅ Finds API endpoints in `window.__INITIAL_STATE__`
- ✅ Discovers WebSocket connections

## Features

### 1. **Headless Chrome Integration**
- Runs Chrome in headless mode (no GUI)
- Full JavaScript execution
- Automatic Chrome download (first run)

### 2. **Network Traffic Monitoring**
- Captures all HTTP requests
- Filters for API-like patterns:
  - `/api/*`, `/v1/*`, `/v2/*`, `/v3/*`
  - `/graphql`, `/rest/*`, `/rpc/*`
  - `*.json` files
  - `/ajax/*`, `/fetch/*`, `/data/*`

### 3. **User Interaction Simulation**
- **Scrolling**: Triggers infinite scroll/lazy loading
- **Clicking**: Activates buttons and links
- **Hovering**: Triggers prefetch mechanisms
- **Waiting**: Allows async operations to complete

### 4. **JavaScript Source Analysis**
- Extracts URLs from `<script>` tags
- Finds API endpoints in:
  - `fetch()` calls
  - `axios.*()` calls
  - `.get()`, `.post()` patterns
  - `window.__STATE__` objects

## Usage

### Basic Browser Discovery
```bash
api_hunter scan https://target.com --with-browser
```

### With Custom Wait Time
```bash
# Wait 10 seconds for page to fully load
api_hunter scan https://target.com --with-browser --browser-wait-ms 10000
```

### Multi-Page Crawl
```bash
# Crawl 3 levels deep
api_hunter scan https://target.com --with-browser --browser-depth 3
```

### Full Feature Scan
```bash
api_hunter scan https://target.com \
  --with-browser \
  --deep-analysis \
  --scan-admin \
  --fuzz-params \
  --aggressive --confirm-aggressive
```

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--with-browser` | false | Enable browser-based discovery |
| `--browser-wait-ms` | 3000 | Milliseconds to wait for page load |
| `--browser-depth` | 1 | Number of pages to crawl |

## How It Works

### 1. Browser Launch
```
[*] Launching headless browser for dynamic API discovery...
```
- Downloads Chrome (if not present)
- Starts headless instance
- Configures stealth mode

### 2. Page Loading
```
[*] Loading page: https://target.com
```
- Navigates to target URL
- Waits for JavaScript execution
- Monitors network traffic

### 3. Interaction Simulation
```
[*] Simulating user interactions...
```
- Scrolls to bottom (lazy loading)
- Clicks visible buttons (AJAX calls)
- Hovers over elements (prefetch)

### 4. API Extraction
```
[+] Browser discovery: 42 API endpoints found
```
- Filters API-like requests
- Deduplicates URLs
- Adds to candidate list

## Examples

### React/Vue/Angular SPAs
```bash
# These apps load APIs dynamically
api_hunter scan https://app.example.com --with-browser --browser-wait-ms 5000
```

### GraphQL Endpoints
```bash
# GraphQL often hidden in JS bundles
api_hunter scan https://api.example.com/graphql --with-browser
```

### Authenticated APIs
```bash
# Load page with cookies/localStorage
# (Future feature: --browser-cookies flag)
api_hunter scan https://app.example.com --with-browser
```

### Bug Bounty Programs
```bash
# Linktree example
api_hunter scan https://linktr.ee --with-browser --deep-analysis --scan-admin
```

## Performance

### Resource Usage
- **Memory**: ~500MB per browser instance
- **CPU**: High during page load, low afterwards
- **Disk**: ~200MB for Chrome binary (first run only)

### Speed
- **Fast**: 3-5 seconds per page (default wait)
- **Standard**: 5-10 seconds per page
- **Thorough**: 10-15 seconds per page

### Optimization Tips
```bash
# Lite mode (faster, less resources)
api_hunter scan target.com --with-browser --lite

# Reduce wait time (faster, may miss APIs)
api_hunter scan target.com --with-browser --browser-wait-ms 2000

# Increase wait time (slower, more thorough)
api_hunter scan target.com --with-browser --browser-wait-ms 8000
```

## API Patterns Detected

### URL Patterns
- `/api/v1/users`
- `/api/v2/posts`
- `/graphql`
- `/rest/endpoint`
- `/data.json`
- `/ajax/load`

### Framework Patterns
- **NextJS**: `/_next/data/`
- **Nuxt**: `/_nuxt/`
- **Gatsby**: `/page-data/`
- **React**: `/static/js/main.*.js`

### Common Endpoints
- `/api/auth/*`
- `/api/user/*`
- `/api/search`
- `/api/config`
- `/v1/graphql`

## Troubleshooting

### Chrome Download Fails
```
[!] Browser discovery failed: Failed to launch browser
```
**Solution**: Manually download Chrome to `~/.cache/chromiumoxide/`

### Timeout Issues
```
[!] Browser discovery timed out
```
**Solution**: Increase wait time:
```bash
--browser-wait-ms 10000
```

### No APIs Found
```
[+] Browser discovery: 0 API endpoints found
```
**Solutions**:
1. Increase wait time (page may load slowly)
2. Check if page requires authentication
3. Try with `--browser-depth 2` for multi-page discovery

### High Memory Usage
```
Memory: 2GB+ used by Chrome
```
**Solution**: Use lite mode or reduce depth:
```bash
--lite --browser-depth 1
```

## Comparison

| Method | Static JS | Browser | Wayback | GAU |
|--------|-----------|---------|---------|-----|
| **Speed** | ⚡⚡⚡ | ⚡ | ⚡⚡ | ⚡⚡ |
| **Accuracy** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **SPAs** | ❌ | ✅ | ❌ | ❌ |
| **Dynamic APIs** | ❌ | ✅ | ❌ | ❌ |
| **Historical** | ❌ | ❌ | ✅ | ✅ |
| **Resources** | Low | High | Low | Low |

## Best Practices

### 1. Combine Methods
```bash
# Use all discovery methods for maximum coverage
api_hunter scan target.com \
  --with-browser \
  --with-wayback \
  --with-gau
```

### 2. Start Small
```bash
# Test with lite mode first
api_hunter scan target.com --with-browser --lite
```

### 3. Increase Depth Gradually
```bash
# Start with depth 1
api_hunter scan target.com --with-browser --browser-depth 1

# If needed, increase to 2-3
api_hunter scan target.com --with-browser --browser-depth 2
```

### 4. Monitor Resources
```powershell
# Check Chrome processes
Get-Process chrome* | Measure-Object WorkingSet -Sum
```

## Future Enhancements

### Planned Features
- 🔄 Cookie/LocalStorage injection for authenticated scans
- 🔄 Custom user interactions (click specific elements)
- 🔄 Screenshot capture of API responses
- 🔄 WebSocket endpoint discovery
- 🔄 Service Worker API interception
- 🔄 Multi-browser support (Firefox, Safari)

### Experimental
- Browser extension mode (real browser with GUI)
- Har file export (full network trace)
- GraphQL introspection queries
- API schema extraction

## Technical Details

### Architecture
```
┌─────────────────────────────────────────┐
│         API Hunter Main Process         │
└────────────────┬────────────────────────┘
                 │
                 ├─► Static JS Extraction
                 ├─► Wayback Machine
                 ├─► GAU Tool
                 │
                 └─► Browser Discovery ◄─┐
                         │                │
                         ▼                │
              ┌──────────────────┐        │
              │  Headless Chrome │        │
              └──────────┬───────┘        │
                         │                │
                    ┌────▼─────┐          │
                    │  Pages   │          │
                    └────┬─────┘          │
                         │                │
                    ┌────▼──────────┐     │
                    │ Network Trace │─────┘
                    └───────────────┘
                         │
                    ┌────▼─────────┐
                    │ API Extractor│
                    └──────────────┘
```

### Chrome DevTools Protocol (CDP)
- Direct communication with Chrome
- Full browser automation
- Network event interception
- JavaScript injection

### Stealth Mode
- Disables automation detection
- Removes `webdriver` property
- Spoofs user agent
- Mimics human behavior

## Conclusion

Browser-based discovery is **essential** for modern web applications. It finds APIs that traditional tools miss and provides the most accurate results for SPAs and dynamic content.

**Recommended for**:
- Bug bounty hunting
- Security assessments of modern apps
- API discovery on React/Vue/Angular sites
- GraphQL endpoint enumeration
- Testing authenticated endpoints

**Not recommended for**:
- Static websites
- Resource-constrained environments
- Bulk scanning (use static methods)

---

**Version**: 1.0  
**Last Updated**: November 2025  
**Status**: Production Ready
