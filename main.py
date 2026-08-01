#!/usr/bin/env python3
import sys
import re
import time
import json
import ssl
import socket
import datetime
import threading
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    from colorama import Fore, Style, init
except ImportError as e:
    print(f"Missing: {e}. Run: pip install requests colorama")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# ==================== LOGGER ====================
def log_info(msg, color='green'):
    colors = {'green': Fore.GREEN, 'red': Fore.RED, 'yellow': Fore.YELLOW,
              'cyan': Fore.CYAN, 'magenta': Fore.MAGENTA, 'blue': Fore.BLUE}
    print(f"{colors.get(color, Fore.WHITE)}{msg}{Style.RESET_ALL}")

# ==================== HTTP CLIENT ====================
def get_session(proxy=None):
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.verify = False
    return session

# ==================== CRAWLER ====================
class Crawler:
    def __init__(self, base_url, proxy=None, max_depth=2):
        self.base_url = base_url.rstrip('/')
        self.session = get_session(proxy)
        self.max_depth = max_depth
        self.visited = set()
        self.urls = set()
        self.forms = []
        self.js_endpoints = set()
        self.params = set()
        self.lock = threading.Lock()

    def crawl(self):
        self._crawl_page(self.base_url, 0)
        return {
            'urls': list(self.urls),
            'forms': self.forms,
            'js_endpoints': list(self.js_endpoints),
            'params': list(self.params)
        }

    def _crawl_page(self, url, depth):
        if depth > self.max_depth or url in self.visited:
            return
        with self.lock:
            self.visited.add(url)
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=True)
            if resp.status_code != 200:
                return
            html = resp.text
            for link in re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
                abs_url = urljoin(url, link)
                if self._same_domain(abs_url) and abs_url not in self.visited:
                    self.urls.add(abs_url)
                    if depth < self.max_depth:
                        self._crawl_page(abs_url, depth + 1)
            for action, content in re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.I | re.S):
                action_url = urljoin(url, action)
                method = 'POST' if 'method="post"' in content.lower() else 'GET'
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', content, re.I)
                self.forms.append({'action': action_url, 'method': method, 'params': inputs})
            for js in re.findall(r'<script[^>]*src=["\']([^"\']+\.js)["\']', html, re.I):
                self.js_endpoints.add(urljoin(url, js))
            parsed = urlparse(url)
            if parsed.query:
                for key in parse_qs(parsed.query):
                    self.params.add(key)
        except Exception:
            pass

    def _same_domain(self, url):
        try:
            return urlparse(url).netloc == urlparse(self.base_url).netloc or urlparse(url).netloc == ''
        except:
            return False

# ==================== FINGERPRINT ====================
class Fingerprinter:
    def __init__(self, url, proxy=None):
        self.url = url
        self.session = get_session(proxy)

    def detect(self):
        tech = {}
        try:
            resp = self.session.get(self.url, timeout=8)
            headers = resp.headers
            html = resp.text
            if headers.get('Server'):
                tech['server'] = headers['Server']
            if 'wp-content' in html or 'wp-includes' in html:
                tech['cms'] = 'WordPress'
            elif 'Joomla!' in html:
                tech['cms'] = 'Joomla'
            elif 'Drupal' in html:
                tech['cms'] = 'Drupal'
            powered = headers.get('X-Powered-By', '')
            if 'PHP' in powered:
                tech['language'] = 'PHP'
            elif 'ASP.NET' in powered:
                tech['language'] = 'ASP.NET'
            elif 'Express' in powered:
                tech['language'] = 'Node.js'
            if 'cloudflare' in headers.get('CF-RAY', '').lower():
                tech['waf'] = 'Cloudflare'
        except:
            pass
        return tech

# ==================== REPORT ====================
def generate_report(findings, target, tech_stack, output_dir="./reports"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('https://', '').replace('http://', '').replace('/', '_')
    base = f"{output_dir}/vulnscan_{safe_target}_{timestamp}"

    with open(f"{base}.json", 'w') as f:
        json.dump({'target': target, 'timestamp': timestamp, 'tech_stack': tech_stack, 'findings': findings}, f, indent=2, default=str)

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        sev = f['severity'].upper()
        if sev in counts:
            counts[sev] += 1

    findings_html = ""
    for f in findings:
        findings_html += f"""
        <div class="finding">
            <span class="badge {f['severity'].lower()}">{f['severity']}</span>
            <span class="title">{f['title']}</span>
            <div class="desc">{f['description']}</div>
            {f'<div class="evidence">{f["evidence"]}</div>' if f.get('evidence') else ''}
            <div class="timestamp">{f['timestamp']}</div>
        </div>
        """

    tech_html = "".join([f"<li><strong>{k}:</strong> {v}</li>" for k, v in tech_stack.items()])

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>VulnScan Report</title>
        <style>
            body{{font-family:sans-serif;background:#f5f7fa;padding:20px;color:#2c3e50;}}
            .container{{max-width:1100px;margin:0 auto;background:#fff;padding:30px;border-radius:12px;}}
            h1{{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px;}}
            .meta{{display:flex;flex-wrap:wrap;gap:20px;background:#f8f9fa;padding:15px;border-radius:8px;margin:15px 0;}}
            .badge{{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:bold;font-size:0.8em;color:#fff;}}
            .critical{{background:#c0392b;}}.high{{background:#e67e22;}}.medium{{background:#f39c12;}}.low{{background:#3498db;}}.info{{background:#95a5a6;}}
            .finding{{border-left:5px solid #3498db;padding:15px 20px;margin:15px 0;background:#fafbfc;border-radius:4px;}}
            .finding .title{{font-weight:600;font-size:1.05em;margin-left:8px;}}
            .finding .evidence{{background:#ecf0f1;padding:10px;border-radius:4px;white-space:pre-wrap;font-family:monospace;font-size:0.85em;max-height:200px;overflow:auto;}}
            .footer{{margin-top:30px;border-top:1px solid #ddd;padding-top:15px;color:#999;text-align:center;}}
            .summary-grid{{display:flex;gap:15px;flex-wrap:wrap;margin:15px 0;}}
            .summary-item{{background:#f8f9fa;padding:10px 20px;border-radius:8px;text-align:center;flex:1;min-width:80px;}}
            .summary-item .number{{font-size:24px;font-weight:bold;}}
            .summary-item.critical .number{{color:#c0392b;}}
            .summary-item.high .number{{color:#e67e22;}}
            .summary-item.medium .number{{color:#f39c12;}}
            .summary-item.low .number{{color:#3498db;}}
            .summary-item.info .number{{color:#95a5a6;}}
        </style>
    </head>
    <body>
    <div class="container">
        <h1>VulnScan Security Audit Report</h1>
        <div class="meta">
            <span><strong>Target:</strong> {target}</span>
            <span><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
            <span><strong>Findings:</strong> {len(findings)}</span>
        </div>
        <div class="summary-grid">
            <div class="summary-item critical"><div class="number">{counts['CRITICAL']}</div>Critical</div>
            <div class="summary-item high"><div class="number">{counts['HIGH']}</div>High</div>
            <div class="summary-item medium"><div class="number">{counts['MEDIUM']}</div>Medium</div>
            <div class="summary-item low"><div class="number">{counts['LOW']}</div>Low</div>
            <div class="summary-item info"><div class="number">{counts['INFO']}</div>Info</div>
        </div>
        <h3>Tech Stack</h3>
        <ul>{tech_html}</ul>
        <h3>Findings</h3>
        {findings_html if findings_html else '<p>No vulnerabilities found.</p>'}
        <div class="footer">Generated by VulnScan</div>
    </div>
    </body>
    </html>
    """

    with open(f"{base}.html", 'w') as f:
        f.write(html)

    return f"{base}.html"

# ==================== ENGINE ====================
from scanners import ALL_SCANNERS

class ScanEngine:
    def __init__(self, target_url, proxy=None):
        self.target_url = target_url.rstrip('/')
        self.proxy = proxy
        self.findings = []
        self.tech_stack = {}
        self.total_methods = len(ALL_SCANNERS)
        self.current_method = 0
        self.stop = False

    def run_interactive(self):
        log_info("Fingerprinting target...", "cyan")
        fp = Fingerprinter(self.target_url, self.proxy)
        self.tech_stack = fp.detect()
        log_info(f"Tech Stack: {self.tech_stack}", "yellow")

        log_info("Crawling target...", "cyan")
        crawler = Crawler(self.target_url, self.proxy)
        crawled = crawler.crawl()

        urls = crawled['urls']
        forms = crawled['forms']
        params = crawled['params']
        js_endpoints = crawled['js_endpoints']

        log_info(f"Found: {len(urls)} URLs, {len(forms)} forms, {len(params)} params", "green")

        for idx, scanner_class in enumerate(ALL_SCANNERS):
            if self.stop:
                break

            self.current_method = idx + 1
            scanner = scanner_class(self.target_url, self.proxy)
            scanner.set_context(urls=urls, forms=forms, params=params, js_endpoints=js_endpoints)

            method_name = scanner.__class__.__name__.replace('Scanner', '')
            log_info(f"[{self.current_method}/{self.total_methods}] Scanning: {method_name}", "magenta")

            progress_thread = threading.Thread(target=self._show_progress, args=(method_name,))
            progress_thread.daemon = True
            progress_thread.start()

            findings = scanner.scan()

            if findings:
                for f in findings:
                    log_info(f"  [!] {f['severity']}: {f['title']}", "red")
                    self.findings.append(f)

            if self.current_method < self.total_methods:
                print("[?] Continue to next method? (y/n): ", end="")
                choice = input().strip().lower()
                if choice != 'y':
                    log_info("Scan stopped by user.", "yellow")
                    self.stop = True
                    break

        log_info("Scan complete.", "green")
        return self.findings

    def _show_progress(self, method_name):
        dots = 0
        while not self.stop and self.current_method <= self.total_methods:
            time.sleep(5)
            dots = (dots + 1) % 4
            sys.stdout.write(f"\r[~] Scanning {method_name}{'.' * dots} (5s)")
            sys.stdout.flush()
        sys.stdout.write("\r")
        sys.stdout.flush()

# ==================== MAIN ====================
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
