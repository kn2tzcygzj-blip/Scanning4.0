#!/usr/bin/env python3

import sys
from engine import ScanEngine
from logger import log_info
from report import generate_report

LOGO = """
\033[94m
__      __    _       _____                 
\ \    / /   | |     / ____|                
 \ \  / /   _| |_ __| (___   ___ __ _ _ __  
  \ \/ / | | | | '_ \\___ \\ / __/ _` | '_ \\ 
   \\  /| |_| | | | | |___) | (_| (_| | | | |
    \\/  \\__,_|_| |_|____/ \\___\\__,_|_| |_|
\033[0m
        \033[94m[ VulnScan v1.0 ]\033[0m
   \033[94mWebsite Security Scanner & Auditor\033[0m
"""

def main():
    print(LOGO)
    print("[+] Enter Target URL")
    target = input("> ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    print("[+] Proxy (kosongkan jika tidak):")
    proxy = input("> ").strip()
    if not proxy:
        proxy = None

    engine = ScanEngine(target, proxy)
    findings = engine.run_interactive()

    report_path = generate_report(findings, target, engine.tech_stack)
    print(f"[+] Report: {report_path}")
    print(f"[+] Total findings: {len(findings)}")

    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    if critical > 0 or high > 0:
        print(f"[!] {target} has CRITICAL/HIGH vulnerabilities!")
    else:
        print(f"[+] {target} no critical/high vulnerabilities.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
        sys.exit(0)
