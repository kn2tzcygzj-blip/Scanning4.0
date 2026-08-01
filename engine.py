import re
from http_client import get_session

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
