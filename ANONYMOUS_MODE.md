# 🥷 Anonymous Scanning Mode  API_Hunter supports anonymous scanning through Tor proxies with IP rotation and randomized headers to protect your identity during reconnaissance.  ## Features  ### 🔐 Privacy & Anonymity
- **Tor SOCKS5 Proxies**: Routes all traffic through Tor network
- **IP Rotation**: Automatic rotation between multiple Tor nodes
- **User-Agent Randomization**: Rotates between 10+ realistic browser fingerprints
- **Random Delays**: 500ms-2s delays between requests to avoid pattern detection
- **Stealth Mode**: HTTP/1.1 only, reduced connection pooling, randomized headers  ### 🌐 Supported Proxies
1. **Local Tor** (recommended):  - `socks5://127.0.0.1:9050` - Tor service  - `socks5://127.0.0.1:9150` - Tor Browser  2. **Custom Proxies**: Use `--proxy` to specify any SOCKS5 proxy  3. **Fallback**: Public Tor bridges (if local unavailable)  ---  ## 🚀 Quick Start  ### 1. Install Tor  #### Windows:
```powershell
# Option 1: Download Tor Browser (easiest)
# Download from: https://www.torproject.org/download/
# Run Tor Browser → SOCKS5 proxy starts on 127.0.0.1:9150  # Option 2: Install standalone Tor
choco install tor
tor --service install
net start tor
```  #### Linux:
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install tor
sudo systemctl start tor
sudo systemctl enable tor  # Arch Linux
sudo pacman -S tor
sudo systemctl start tor
```  #### macOS:
```bash
brew install tor
brew services start tor
```  ### 2. Verify Tor is Running  ```bash
# Check if Tor is accessible
curl --proxy socks5h://127.0.0.1:9050 https://check.torproject.org  # Should return: "Congratulations. This browser is configured to use Tor."
```  ### 3. Run Anonymous Scan  ```bash
# Basic anonymous scan
cargo run --release -- scan https://target.com --anonymous  # Anonymous with deep analysis
cargo run --release -- scan https://target.com \  --anonymous \  --deep-analysis \  --scan-admin  # Anonymous with custom proxy
cargo run --release -- scan https://target.com \  --anonymous \  --proxy socks5://127.0.0.1:9050
```  ---  ## 📋 Usage Examples  ### Basic Anonymous Reconnaissance
```bash
# Lite mode with Tor (low detection risk)
cargo run --release -- scan https://target.com \  --anonymous \  --lite
``` **Output:**
```
🥷 Anonymous Mode Enabled
🔍 Checking for Tor installation...
🔐 Creating anonymous HTTP client with Tor routing...
🥷 Stealth Mode: Tor proxy 127.0.0.1:9050 | Randomized headers
✅ Anonymous client ready
```  ### Advanced Anonymous Scanning
```bash
# Full anonymous scan with all features
cargo run --release -- scan https://target.com \  --anonymous \  --deep-analysis \  --scan-admin \  --advanced-idor \  --fuzz-params \  --timeout 180 \  --concurrency 20
``` **Features**:
- ✅ Traffic routed through Tor
- ✅ Random User-Agent per request
- ✅ 500ms-2s delays between requests
- ✅ HTTP/1.1 only (less fingerprinting)
- ✅ Reduced connection pooling
- ✅ All requests appear from different IPs (Tor circuit rotation)  ### Using Custom Proxy
```bash
# Use your own SOCKS5 proxy
cargo run --release -- scan https://target.com \  --anonymous \  --proxy socks5://your-proxy.com:1080  # Chain multiple proxies (external setup required)
cargo run --release -- scan https://target.com \  --anonymous \  --proxy socks5://127.0.0.1:9050
```  ### Multiple Scans with IP Rotation
```bash
# Tor automatically rotates IPs every ~10 minutes
# For faster rotation, restart Tor between scans:  for target in target1.com target2.com target3.com; do  echo "Scanning $target..."  cargo run --release -- scan https://$target --anonymous --lite  # Force new Tor circuit (new IP)  echo "Rotating Tor circuit..."  systemctl restart tor  sleep 10
done
```  ---  ## 🛡️ Security Features  ### Traffic Obfuscation
```
Your IP → Tor Entry → Tor Middle → Tor Exit → Target  🔒  🔒  🔒  🔒
``` **What target sees:**
- ❌ Your real IP: `Hidden`
- ✅ Tor exit node IP: `Different every 10 minutes`
- ✅ Random User-Agent: `Looks like normal browser`
- ✅ Random timing: `No obvious bot patterns`  ### Anti-Detection Measures  1. **User-Agent Rotation** (10+ variants):  - Chrome 120 (Windows/Mac/Linux)  - Firefox 121 (Windows/Mac/Linux)  - Safari 17 (macOS/iOS)  - Mobile browsers (Android/iOS)  - Tor Browser  2. **Random Delays**:  - 500-2000ms between requests  - Mimics human browsing patterns  - Avoids rate limit triggers  3. **Stealth HTTP Configuration**:  - HTTP/1.1 only (no HTTP/2 fingerprinting)  - Small connection pools (5 per host vs 300)  - 30s idle timeout (vs 90s)  - No persistent connections  4. **Request Patterns**:  - Randomized request order  - Natural timing variations  - No burst traffic patterns  ---  ## ⚙️ Configuration  ### Environment Variables
```bash
# Override default Tor proxy
export TOR_PROXY=socks5://127.0.0.1:9050  # Set custom delays (milliseconds)
export ANON_MIN_DELAY=1000
export ANON_MAX_DELAY=3000
```  ### Tor Configuration (`/etc/tor/torrc`)
```ini
# Faster circuit rotation (every 2 minutes instead of 10)
MaxCircuitDirtiness 120  # Use specific exit countries (optional)
ExitNodes {US},{GB},{DE}
StrictNodes 1  # Increase connection limit
ConnLimit 1024  # Enable control port for circuit management
ControlPort 9051
HashedControlPassword <your-hashed-password>
```  Reload Tor after changes:
```bash
sudo systemctl reload tor
```  ---  ## 🔍 Verification  ### Test Anonymous Connection
```bash
# Check your Tor IP
curl --proxy socks5h://127.0.0.1:9050 https://api.ipify.org
# Output: <Tor Exit Node IP>  # Compare with your real IP
curl https://api.ipify.org
# Output: <Your Real IP>  # They should be DIFFERENT!
```  ### Monitor Tor Circuits
```bash
# Install tor-arm for live monitoring
sudo apt install tor-arm
sudo arm  # Or check logs
sudo journalctl -u tor -f
```  ### Verify Traffic is Proxied
```bash
# Run Wireshark/tcpdump on your network interface
# You should see ONLY encrypted traffic to Tor entry nodes
# NO direct connections to target domains
```  ---  ## 📊 Performance Impact  ### Speed Comparison  | Mode | Requests/sec | Latency | Anonymity | |------|--------------|---------|-----------| | **Direct** | 100-200 | ~50ms | ❌ None | | **Tor (default)** | 10-20 | ~500ms | ✅ High | | **Tor (stealth)** | 5-10 | ~1000ms | ✅✅ Maximum | ### Tor Overhead
- **Latency**: +300-800ms per request (3 hops)
- **Throughput**: ~70% slower (Tor bandwidth limits)
- **Reliability**: ~95% (some circuits fail)  ### Optimization Tips
```bash
# Use --lite for faster anonymous scans
cargo run --release -- scan https://target.com --anonymous --lite  # Increase concurrency (more parallel Tor circuits)
cargo run --release -- scan https://target.com \  --anonymous \  --concurrency 50  # Use shorter timeouts
cargo run --release -- scan https://target.com \  --anonymous \  --timeout 60
```  ---  ## 🚨 Warnings & Legal  ### ⚠️ Important Disclaimers  1. **Legal Use Only**:  - Anonymous scanning does NOT make illegal activities legal  - Only scan systems you have permission to test  - Bug bounty programs: Check if Tor scanning is allowed  2. **Tor Exit Nodes**:  - Exit nodes can see unencrypted traffic  - Use HTTPS for all sensitive requests (API_Hunter does this by default)  - Some sites block Tor exit IPs  3. **Detection Risk**:  - Advanced WAFs can still detect automated scanning  - Tor usage itself may trigger alerts  - Some targets log and ban Tor IPs  4. **Performance**:  - Tor is significantly slower (~5-10x)  - Use `--lite` mode for long scans  - Circuit failures will cause request errors  ### ✅ Best Practices  ```bash
# 1. Always use --lite for anonymous recon
cargo run --release -- scan https://target.com --anonymous --lite  # 2. Add extra delays between scans
cargo run --release -- scan https://target.com --anonymous --timeout 180  # 3. Monitor for blocks/bans
# If you see many 403/429 errors, Tor IPs may be blocked  # 4. Use burner domains for testing
# Don't mix anonymous scans with authenticated scans  # 5. Verify Tor is working before starting
curl --proxy socks5h://127.0.0.1:9050 https://check.torproject.org
```  ---  ## 🛠️ Troubleshooting  ### Problem: "Failed to create anonymous client"
```
⚠️  Failed to create anonymous client: error trying to connect: tcp connect error: Connection refused
``` **Solution:**
1. Check if Tor is running:  ```bash  # Linux  sudo systemctl status tor  # Windows  tasklist | findstr tor  ```  2. Verify Tor port:  ```bash  netstat -an | grep 9050  # Should show: 127.0.0.1:9050 LISTENING  ```  3. Test Tor connection:  ```bash  curl --proxy socks5h://127.0.0.1:9050 https://check.torproject.org  ```  ### Problem: "Tor exit nodes blocked"
```
Many 403 Forbidden or 503 Service Unavailable errors
``` **Solution:**
1. Some sites block all Tor IPs
2. Try different Tor exit countries:  ```ini  # /etc/tor/torrc  ExitNodes {US}  StrictNodes 1  ```
3. Use custom proxy instead:  ```bash  --proxy socks5://your-private-proxy:1080  ```  ### Problem: "Very slow scans"
```
Requests taking 10+ seconds each
``` **Solution:**
1. Tor adds latency - this is expected
2. Use `--lite` mode:  ```bash  --anonymous --lite --concurrency 10  ```
3. Increase timeout:  ```bash  --anonymous --timeout 30  ```  ### Problem: "Connection timeout"
```
Error: request timeout after 10s
``` **Solution:**
1. Increase timeout for Tor:  ```bash  --timeout 30  # or --timeout 60 for very slow circuits  ```
2. Some Tor circuits are slow - API_Hunter will retry
3. Check Tor logs:  ```bash  sudo journalctl -u tor -f  ```  ---  ## 🎯 Example Scenarios  ### Bug Bounty Reconnaissance
```bash
# Phase 1: Quick anonymous recon (find endpoints)
cargo run --release -- scan https://target.com \  --anonymous \  --lite \  --timeout 60  # Phase 2: Deep analysis (non-anonymous from allowed IP)
cargo run --release -- scan https://target.com \  --deep-analysis \  --scan-admin \  --advanced-idor
```  ### Red Team Operation
```bash
# Full stealth scan with all features
cargo run --release -- scan https://target.com \  --anonymous \  --proxy socks5://127.0.0.1:9050 \  --lite \  --deep-analysis \  --timeout 180 \  --concurrency 10  # Rotate Tor circuit every 100 requests
# (External script to send NEWNYM signal to Tor)
```  ### Competitive Intelligence (Legal)
```bash
# Analyze competitor APIs anonymously
cargo run --release -- scan https://competitor.com \  --anonymous \  --lite \  --timeout 120  # Results show API structure without revealing your company IP
```  ---  ## 📚 Additional Resources  - **Tor Project**: https://www.torproject.org/
- **Tor Browser**: https://www.torproject.org/download/
- **SOCKS5 Proxy Guide**: https://en.wikipedia.org/wiki/SOCKS
- **Check Tor Connection**: https://check.torproject.org/
- **Tor Metrics**: https://metrics.torproject.org/  ---  ## 🔐 Privacy Guarantee  When using `--anonymous`:
- ✅ Real IP hidden behind Tor network
- ✅ User-Agent randomized (no fingerprinting)
- ✅ Timing patterns randomized (no bot detection)
- ✅ Traffic encrypted (Tor → Target)
- ✅ No logs stored with identifying info **What we DON'T log**:
- Your real IP address
- Your system information
- Proxy credentials
- Request/response contents (unless you save them) **What we DO log** (locally only):
- Found API endpoints
- Response status codes
- Vulnerability findings
- Scan timing and statistics  All data stays on your machine unless you explicitly share it.  ---  ## 🆘 Support  If you encounter issues with anonymous mode:  1. Check Tor status: `systemctl status tor`
2. Verify proxy: `curl --proxy socks5h://127.0.0.1:9050 https://check.torproject.org`
3. Review logs: `sudo journalctl -u tor -f`
4. Open issue: https://github.com/mmadersbacher/API_Hunter/issues **Happy Anonymous Hunting! 🥷🔍**
