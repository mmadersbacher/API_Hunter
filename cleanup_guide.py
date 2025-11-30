#!/usr/bin/env python3
"""
Script to clean up verbose println! and tracing statements from runner.rs
This will be manually applied based on the logic here.
"""

# Remove these verbose println! statements:
verbose_patterns_to_remove = [
    'println!("[*] Cleaning previous scan results...");',
    'println!("[-] Removed: {}", path.file_name()...',
    'println!("[+] Results directory cleaned");',
    'println!("[+] Created results directory: {}", results_dir);',
    'println!("[+] Found {} subdomains"',
    'println!("[+] Subdomain report saved to: {}"',
    'println!("[+] Adding API subdomain to scan: {}"',
    'println!("[+] Total targets to scan: {}"',
    'println!("[*] Deep JS Analysis: Scanning..."',  # Replace with cleaner version
    'println!("    [+] Endpoints: {}"',  # Combine into one line
    'tracing::info!',  # Most of these
    'tracing::debug!',  # All of these
]

# Keep only essential output:
essential_patterns_to_keep = [
    'println!("\\n╔══..."',  # Scan headers
    'println!("[*] Target: {}"',
    'println!("📊 Summary:")',
    'println!("🔍 Security Findings:")',
    # Severity emoji outputs
    # Final summary
]
