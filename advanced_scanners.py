import re
import time
import json
import base64
import urllib.parse
import hashlib
from scanners import BaseScanner
from utils import is_false_positive, time_based_test, encode_payload

# ============================
# NOSQL INJECTION
# ============================
class NoSQLiScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['id', 'user', 'q', 'search'])
        payloads = [
            "{'$ne': ''}", "{'$gt': ''}", "{'$regex': '.*'}",
            "{'$where': '1==1'}", "{'$or': [{'a': 'b'}, {'a': 'b'}]}"
        ]
        for param in params[:5]:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if 'MongoError' in resp.text or 'MongoDB' in resp.text:
                        findings.append(self._add_finding(
                            'HIGH', 'NoSQL Injection', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

# ============================
# SSRF ADVANCED
# ============================
class SSRFScanner(BaseScanner):
    def scan(self):
        findings = []
        params = self.context.get('params', ['url', 'src', 'dest', 'redirect', 'path'])
        payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/',
            'http://127.0.0.1:8080',
            'http://localhost:8080',
            'http://[::1]:8080',
            'http://169.254.169.254/latest/user-data/',
        ]
        for param in params[:5]:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                resp = self._safe_get(test_url)
                if resp and resp.status_code == 200:
                    if '169.254' in resp.text or 'metadata' in resp.text or 'localhost' in resp.text:
                        findings.append(self._add_finding(
                            'HIGH', 'SSRF', f'Parameter {param} vulnerable', resp.text[:300]
                        ))
                        break
        return findings

# ============================
# JWT WEAKNESS
# ============================
class JWTScanner(BaseScanner):
    def scan(self):
        findings = []
        # Simulasi: cek cookie / header Authorization
        try:
            resp = self._safe_get(self.target_url)
            if not resp:
                return findings
            auth = resp.headers.get('Authorization', '')
            if 'Bearer' in auth:
                token = auth.replace('Bearer ', '')
                if token.count('.') == 2:
                    # Cek algoritma 'none'
                    import base64, json
                    header = json.loads(base64.b64decode(token.split('.')[0] + '=='))
                    if header.get('alg') == 'none':
                        findings.append(self._add_finding(
                            'HIGH', 'JWT None Algorithm', 'JWT uses "none" algorithm', token
                        ))
        except:
            pass
        return findings

# ============================
# GRAPHQL INTROSPECTION
# ============================
class GraphQLScanner(BaseScanner):
    def scan(self):
        findings = []
        paths = ['/graphql', '/v1/graphql', '/api/graphql', '/graphiql']
        for path in paths:
            resp = self._safe_get(f"{self.target_url}{path}")
            if resp and resp.status_code == 200:
                if 'GraphQL' in resp.text or 'schema' in resp.text:
                    findings.append(self._add_finding(
                        'MEDIUM', 'GraphQL Endpoint Found', f'{path} accessible', resp.text[:300]
                    ))
                    # Cek introspection
                    query = '{"query":"query { __schema { types { name } } }"}'
                    post_resp = self._safe_post(f"{self.target_url}{path}", data=query)
                    if post_resp and '__schema' in post_resp.text:
                        findings.append(self._add_finding(
                            'HIGH', 'GraphQL Introspection Enabled', 'Schema exposed', post_resp.text[:300]
                        ))
                    break
        return findings

    def _safe_post(self, url, data, timeout=8):
        try:
            return self.session.post(url, data=data, timeout=timeout)
        except:
            return None

# ============================
# CVE CHECKER
# ============================
class CVEScanner(BaseScanner):
    def scan(self):
        findings = []
        # Ambil tech_stack dari context (diisi oleh engine)
        tech = self.context.get('tech_stack', {})
        if 'WordPress' in tech.get('cms', ''):
            findings.append(self._add_finding(
                'HIGH', 'CVE-2023-5360', 'WordPress SQL Injection vulnerability', 'CVE-2023-5360'
            ))
        if 'Apache' in tech.get('server', ''):
            findings.append(self._add_finding(
                'MEDIUM', 'CVE-2021-42013', 'Apache Path Traversal', 'CVE-2021-42013'
            ))
        return findings

# ============================
# RACE CONDITION (SIMULATED)
# ============================
class RaceConditionScanner(BaseScanner):
    def scan(self):
        findings = []
        import threading
        urls = self.context.get('urls', [self.target_url])
        for url in urls[:3]:
            # Coba 5 request paralel ke URL yang sama
            def req():
                try:
                    self.session.get(url, timeout=5)
                except:
                    pass
            threads = [threading.Thread(target=req) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            # Cek apakah ada respon tidak wajar (misal 500 atau 429)
            resp = self._safe_get(url)
            if resp and resp.status_code == 500:
                findings.append(self._add_finding(
                    'MEDIUM', 'Race Condition Possible', f'{url} returned 500 on parallel requests'
                ))
                break
        return findings

# ============================
# FILE UPLOAD DETECTION
# ============================
class FileUploadScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if resp and re.search(r'<input[^>]*type=["\']file["\']', resp.text, re.I):
            findings.append(self._add_finding(
                'MEDIUM', 'File Upload Form Found', 'Possible unrestricted file upload', resp.text[:300]
            ))
        return findings

# ============================
# SENSITIVE HEADER EXPOSURE
# ============================
class SensitiveHeaderScanner(BaseScanner):
    def scan(self):
        findings = []
        resp = self._safe_get(self.target_url)
        if not resp:
            return findings
        sensitive = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for h in sensitive:
            if h in resp.headers:
                findings.append(self._add_finding(
                    'LOW', f'Sensitive Header: {h}', f'{h} exposes technology info', resp.headers[h]
                ))
        return findings
