#!/usr/bin/env python3
import sys
import re
import time
import json
import ssl
import socket
import datetime
import threading
import webbrowser
from urllib.parse import urljoin, urlparse, parse_qs
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

# ==================== HTTP CLIENT ====================
def get_session(proxy=None):
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.verify = False
    return session

# ==================== LOGGER ====================
def log_info(msg, color='green'):
    colors = {'green': Fore.GREEN, 'red': Fore.RED, 'yellow': Fore.YELLOW, 'cyan': Fore.CYAN, 'magenta': Fore.MAGENTA}
    print(f"{colors.get(color, Fore.WHITE)}{msg}{Style.RESET_ALL}")

# ==================== CRAWLER ====================
class Crawler:
    def __init__(self, base_url, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.session = get_session(proxy)
        self.visited = set()
        self.urls = set()
        self.forms = []
        self.params = set()
        self.lock = threading.Lock()
    def crawl(self):
        self._crawl_page(self.base_url, 0)
        return {'urls': list(self.urls), 'forms': self.forms, 'params': list(self.params)}
    def _crawl_page(self, url, depth):
        if depth > 2 or url in self.visited:
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
                    self._crawl_page(abs_url, depth+1)
            for action, content in re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.I | re.S):
                action_url = urljoin(url, action)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', content, re.I)
                self.forms.append({'action': action_url, 'params': inputs})
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

# ==================== SCANNER ====================
class BaseScanner:
    def __init__(self, target_url, proxy=None):
        self.target_url = target_url.rstrip('/')
        self.proxy = proxy
        self.session = get_session(proxy)
        self.context = {}
    def set_context(self, **kwargs):
        self.context.update(kwargs)
    def _add_finding(self, severity, title, description, evidence=""):
        return {'severity': severity.upper(), 'title': title, 'description': description, 'evidence': evidence[:1500] if evidence else "", 'timestamp': datetime.datetime.now().isoformat()}
    def _safe_get(self, url, timeout=8):
        try:
            return self.session.get(url, timeout=timeout, allow_redirects=True)
        except:
            return None

# ==================== SCANNERS ====================
class SQLiScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['id', 'q', 'page'])
        for param in params[:5]:
            for payload in ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200 and re.search(r'(SQL|syntax|mysql|postgres|oracle|sqlite)', resp.text, re.I):
                    findings.append(self._add_finding('CRITICAL', 'SQL Injection', f'Parameter {param} vulnerable', resp.text[:300]))
                    break
        return findings

class XSSScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['q', 'search'])
        for param in params[:5]:
            for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200 and payload in resp.text:
                    findings.append(self._add_finding('HIGH', 'XSS Reflected', f'Parameter {param} vulnerable', resp.text[:300]))
                    break
        return findings

class LFIScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['page', 'file'])
        for param in params[:5]:
            for payload in ["/etc/passwd", "/etc/hosts"]:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200 and re.search(r'(root:|nobody:|/etc/passwd)', resp.text, re.I):
                    findings.append(self._add_finding('HIGH', 'LFI', f'Parameter {param} vulnerable', resp.text[:300]))
                    break
        return findings

class HeadersScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        missing = [h for h in ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security', 'Content-Security-Policy'] if h not in resp.headers]
        if missing:
            findings.append(self._add_finding('MEDIUM', 'Missing Security Headers', f'Missing: {", ".join(missing)}', str(dict(resp.headers))))
        return findings

ALL_SCANNERS = [SQLiScanner, XSSScanner, LFIScanner, HeadersScanner]

# ==================== LOCALHOST SERVER ====================
from flask import Flask, render_template_string

app = Flask(__name__)
FINDINGS = []
TARGET = ""

@app.route('/')
def index():
    counts = {'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0}
    for f in FINDINGS:
        sev = f['severity']
        if sev in counts:
            counts[sev] += 1
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head><title>VulnScan Report</title>
    <style>
        body{font-family:sans-serif;background:#f5f7fa;padding:20px;color:#2c3e50;}
        .container{max-width:1100px;margin:0 auto;background:#fff;padding:30px;border-radius:12px;}
        h1{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px;}
        .badge{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:bold;font-size:0.8em;color:#fff;}
        .critical{background:#c0392b;}.high{background:#e67e22;}.medium{background:#f39c12;}.low{background:#3498db;}
        .finding{border-left:5px solid #3498db;padding:15px 20px;margin:15px 0;background:#fafbfc;border-radius:4px;}
        .evidence{background:#ecf0f1;padding:10px;border-radius:4px;white-space:pre-wrap;font-family:monospace;font-size:0.85em;max-height:200px;overflow:auto;}
        .summary-grid{display:flex;gap:15px;flex-wrap:wrap;margin:15px 0;}
        .summary-item{background:#f8f9fa;padding:10px 20px;border-radius:8px;text-align:center;flex:1;min-width:80px;}
        .summary-item .number{font-size:24px;font-weight:bold;}
        .summary-item.critical .number{color:#c0392b;}
        .summary-item.high .number{color:#e67e22;}
        .summary-item.medium .number{color:#f39c12;}
        .summary-item.low .number{color:#3498db;}
        .download-btn{background:#3498db;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:1em;}
        .footer{margin-top:30px;border-top:1px solid #ddd;padding-top:15px;color:#999;text-align:center;}
    </style>
    </head>
    <body>
    <div class="container">
        <h1>VulnScan Security Audit Report</h1>
        <p><strong>Target:</strong> {{ target }}</p>
        <div class="summary-grid">
            <div class="summary-item critical"><div class="number">{{ counts.CRITICAL }}</div>Critical</div>
            <div class="summary-item high"><div class="number">{{ counts.HIGH }}</div>High</div>
            <div class="summary-item medium"><div class="number">{{ counts.MEDIUM }}</div>Medium</div>
            <div class="summary-item low"><div class="number">{{ counts.LOW }}</div>Low</div>
        </div>
        <h3>Findings</h3>
        {% for f in findings %}
        <div class="finding">
            <span class="badge {{ f.severity.lower() }}">{{ f.severity }}</span>
            <strong>{{ f.title }}</strong>
            <p>{{ f.description }}</p>
            {% if f.evidence %}
            <div class="evidence">{{ f.evidence }}</div>
            {% endif %}
            <small>{{ f.timestamp }}</small>
        </div>
        {% else %}
        <p>No vulnerabilities found.</p>
        {% endfor %}
        <button class="download-btn" onclick="downloadHTML()">Download Report (HTML)</button>
        <div class="footer">Generated by VulnScan</div>
    </div>
    <script>
        function downloadHTML(){
            var html = document.documentElement.outerHTML;
            var blob = new Blob([html], {type:'text/html'});
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'VulnScan_Report_{{ target }}.html';
            a.click();
        }
    </script>
    </body>
    </html>
    """, target=TARGET, findings=FINDINGS, counts=counts)

def run_localhost(port=8080):
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# ==================== ENGINE ====================
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
        global FINDINGS, TARGET
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
        log_info(f"Found: {len(urls)} URLs, {len(forms)} forms, {len(params)} params", "green")

        for idx, scanner_class in enumerate(ALL_SCANNERS):
            if self.stop:
                break
            self.current_method = idx + 1
            scanner = scanner_class(self.target_url, self.proxy)
            scanner.set_context(urls=urls, forms=forms, params=params)
            method_name = scanner.__class__.__name__.replace('Scanner', '')
            log_info(f"[{self.current_method}/{self.total_methods}] Scanning: {method_name}", "magenta")

            # Progress tiap 5 detik
            progress_thread = threading.Thread(target=self._show_progress, args=(method_name,))
            progress_thread.daemon = True
            progress_thread.start()

            findings = scanner.scan()
            if findings:
                for f in findings:
                    log_info(f"  [!] {f['severity']}: {f['title']} - {f['description'][:50]}...", "red")
                    self.findings.append(f)

            if self.current_method < self.total_methods:
                print("\n[?] Continue to next method? (y/n): ", end="")
                choice = input().strip().lower()
                if choice != 'y':
                    log_info("Scan stopped by user.", "yellow")
                    self.stop = True
                    break

        log_info("Scan complete.", "green")
        FINDINGS = self.findings
        TARGET = self.target_url
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
        \033[94m[ VulnScan v4.0 ]\033[0m
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

    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    if critical > 0 or high > 0:
        log_info(f"[!] {target} memiliki CRITICAL/HIGH vulnerability!", "red")
    else:
        log_info(f"[+] {target} tidak memiliki celah CRITICAL/HIGH.", "green")

    print("\n[+] Tekan Enter untuk membuka laporan di localhost (http://localhost:8080)")
    input()
    print("[+] Menjalankan localhost...")
    run_localhost()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
        sys.exit(0)
