import time
import hashlib
import base64
import urllib.parse
import re

# ============================
# VALIDATOR FALSE POSITIVE
# ============================
def is_false_positive(response_text, payload_type='sql'):
    """
    Cek apakah response benar-benar menunjukkan celah atau hanya false positive.
    """
    if payload_type == 'sql':
        sql_keywords = ['sql', 'syntax', 'mysql', 'postgresql', 'oracle', 'sqlite', 'pg::', 'odbc']
        if not any(k in response_text.lower() for k in sql_keywords):
            return True
        # Jika error muncul tapi tidak ada query yang dieksekusi, bisa FP
        if 'stack trace' in response_text.lower() and not 'sql' in response_text.lower():
            return True
    elif payload_type == 'xss':
        if not re.search(r'<script|<img.*onerror|javascript:|<svg/onload', response_text, re.I):
            return True
    elif payload_type == 'lfi':
        if not re.search(r'root:|nobody:|/etc/passwd|windows|boot.ini', response_text, re.I):
            return True
    return False

# ============================
# TIME-BASED DETECTOR
# ============================
def time_based_test(url, param, payload, session, delay=5):
    """
    Tes SQL Injection time-based dengan mengukur waktu response.
    """
    try:
        start = time.time()
        session.get(f"{url}?{param}={payload}", timeout=10)
        elapsed = time.time() - start
        return elapsed >= delay
    except:
        return False

# ============================
# PAYLOAD ENCODER
# ============================
def encode_payload(payload, encoding='url'):
    if encoding == 'url':
        return urllib.parse.quote(payload)
    elif encoding == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif encoding == 'double_url':
        return urllib.parse.quote(urllib.parse.quote(payload))
    return payload

# ============================
# CVE SIMULATOR (NVD MOCK)
# ============================
def check_known_cve(tech_stack):
    """
    Cek CVE berdasarkan tech stack yang terdeteksi.
    """
    cve_list = []
    if 'WordPress' in tech_stack.get('cms', ''):
        cve_list.append('CVE-2023-5360 (WordPress SQL Injection)')
        cve_list.append('CVE-2023-3460 (WordPress XSS)')
    if 'Apache' in tech_stack.get('server', ''):
        cve_list.append('CVE-2021-42013 (Apache Path Traversal)')
    if 'nginx' in tech_stack.get('server', ''):
        cve_list.append('CVE-2017-7529 (Nginx Integer Overflow)')
    return cve_list
