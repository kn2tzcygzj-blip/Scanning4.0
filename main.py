#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import threading
from core.engine import ScanEngine
from utils.logger import log_info, setup_logger
from utils.report import generate_report

VERSION = "5.0-"

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
   \033[94mWebsite Security Scanner & Auditor — Ultimate Edition\033[0m
"""

def interactive_scan():
    print(LOGO)
    print("\n\033[96m[+] Enter Target URL\033[0m")
    target = input("> ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    print("\n\033[96m[+] Proxy (kosongkan jika tidak):\033[0m")
    proxy = input("> ").strip()
    if not proxy:
        proxy = None

    print("\n\033[93m[!] Scanning dimulai...\033[0m")
    engine = ScanEngine(target, proxy)
    
    # Scan dengan interaktif
    findings = engine.run_interactive()
    
    # Generate report
    report_path = generate_report(findings, target, engine.tech_stack)
    
    print(f"\n\033[92m[+] Laporan selesai: {report_path}\033[0m")
    print(f"\n\033[92m[+] Total temuan: {len(findings)}\033[0m")

if __name__ == "__main__":
    try:
        interactive_scan()
    except KeyboardInterrupt:
        print("\n\033[91m[!] Scan dihentikan oleh user.\033[0m")
        sys.exit(0)
