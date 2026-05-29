#!/usr/bin/env python3
"""
bad_parents — TikTok block controller for UniFi Dream Machine
Uses the UniFi v2 API with X-API-KEY header auth (no 2FA required).
"""
import json
import os
import threading
import time
import urllib.request
import urllib.error
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = os.path.dirname(__file__)

TIKTOK_DOMAINS = [
    'tiktok.com',
    'tiktokcdn.com',
    'tiktokv.com',
    'tiktokcdn-us.com',
    'musically.com',
    'byteoversea.com',
]

# ── State ─────────────────────────────────────────────────────────────────────
state = {
    'blocked':    False,
    'unblock_at': None,
    'error':      None,
}
_timer: threading.Timer | None = None
_lock  = threading.Lock()


# ── Config ────────────────────────────────────────────────────────────────────
def cfg():
    with open(os.path.join(BASE, 'config.json')) as f:
        return json.load(f)


# ── UniFi API client ──────────────────────────────────────────────────────────
class UniFiClient:
    def __init__(self, base_url, api_key, site='default'):
        self.base = base_url.rstrip('/')
        self.site = site
        self._key = api_key
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode    = ssl.CERT_NONE

    def _req(self, method, path, body=None):
        url  = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req  = urllib.request.Request(url, data=data, method=method, headers={
            'Content-Type': 'application/json',
            'Accept':       'application/json',
            'X-API-KEY':    self._key,
        })
        with urllib.request.urlopen(req, context=self._ctx) as r:
            return json.loads(r.read())

    def list_rules(self):
        return self._req('GET',
            f'/proxy/network/v2/api/site/{self.site}/trafficrules')

    def create_rule(self, rule):
        return self._req('POST',
            f'/proxy/network/v2/api/site/{self.site}/trafficrules', rule)

    def update_rule(self, rule_id, rule):
        return self._req('PUT',
            f'/proxy/network/v2/api/site/{self.site}/trafficrules/{rule_id}', rule)

    def find_rule(self, name):
        for r in self.list_rules():
            if r.get('description', '').lower() == name.lower():
                return r
        return None

    def ensure_rule(self, name):
        """Return existing rule or create it if absent."""
        rule = self.find_rule(name)
        if rule:
            return rule
        created = self.create_rule({
            'action':          'BLOCK',
            'description':     name,
            'enabled':         False,
            'ip_version':      'BOTH',
            'matching_target': 'DOMAIN',
            'target_devices':  [{'type': 'ALL_CLIENTS'}],
            'schedule':        {'mode': 'ALWAYS'},
            'app_category_ids': [], 'app_ids': [],
            'ip_addresses': [], 'ip_ranges': [],
            'network_ids': [], 'regions': [],
            'bandwidth_limit': {'enabled': False,
                                'download_limit_kbps': 1024,
                                'upload_limit_kbps': 1024},
            'domains': [
                {'domain': d, 'port_ranges': [], 'ports': []}
                for d in TIKTOK_DOMAINS
            ],
        })
        return created

    def set_enabled(self, rule, enabled: bool):
        r = dict(rule)
        r['enabled'] = enabled
        return self.update_rule(r['_id'], r)


# ── Block / unblock ───────────────────────────────────────────────────────────
def _make_client():
    c = cfg()
    return UniFiClient(c['controller_url'], c['api_key'], c.get('site', 'default'))


def _do_unblock():
    with _lock:
        try:
            client = _make_client()
            rule   = client.find_rule(cfg()['rule_name'])
            if rule:
                client.set_enabled(rule, False)
            state.update(blocked=False, unblock_at=None, error=None)
        except Exception as e:
            state['error'] = str(e)


def block_tiktok():
    global _timer
    with _lock:
        try:
            c      = cfg()
            client = _make_client()
            rule   = client.ensure_rule(c['rule_name'])
            client.set_enabled(rule, True)
            duration = int(c.get('block_minutes', 5)) * 60
            state.update(blocked=True, unblock_at=time.time() + duration, error=None)
            if _timer:
                _timer.cancel()
            _timer = threading.Timer(duration, _do_unblock)
            _timer.daemon = True
            _timer.start()
        except Exception as e:
            state['error'] = str(e)


def unblock_tiktok():
    global _timer
    if _timer:
        _timer.cancel()
    _do_unblock()


# ── HTTP server ───────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(fmt % args)

    def do_GET(self):
        if self.path == '/':
            self._file('index.html', 'text/html; charset=utf-8')

        elif self.path == '/api/status':
            c = cfg()
            self._json({
                'blocked':       state['blocked'],
                'unblock_at':    state['unblock_at'],
                'error':         state['error'],
                'block_minutes': c.get('block_minutes', 5),
                'rule_name':     c.get('rule_name', ''),
            })

        elif self.path == '/api/rules':
            try:
                rules = _make_client().list_rules()
                self._json({'rules': [r.get('description', '?') for r in rules]})
            except Exception as e:
                self._json({'error': str(e)}, 502)

        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/api/block':
            threading.Thread(target=block_tiktok, daemon=True).start()
            time.sleep(0.5)
            self._json({'ok': True, 'error': state.get('error')})
        elif self.path == '/api/unblock':
            threading.Thread(target=unblock_tiktok, daemon=True).start()
            time.sleep(0.5)
            self._json({'ok': True})
        else:
            self.send_error(404)

    def _file(self, name, ct):
        try:
            with open(os.path.join(BASE, name), 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('Content-Type', ct)
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_error(404)

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    c    = cfg()
    port = int(c.get('server_port', 8091))
    srv  = HTTPServer(('0.0.0.0', port), Handler)
    print(f'bad_parents running on http://0.0.0.0:{port}')
    srv.serve_forever()
