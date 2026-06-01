#!/usr/bin/env python3
"""
bad_parents — TikTok block controller for UniFi Dream Machine
Uses the UniFi v2 API with X-API-KEY header auth.
Blocks via IP-based traffic rule targeting ByteDance AS prefixes — no DPI required.
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

# IPv4 prefixes for AS396986 (ByteDance Inc) and AS138699 (TikTok PTE Ltd)
TIKTOK_IP_RANGES = [
    '71.18.1.0/24',   '71.18.2.0/23',   '71.18.3.0/24',   '71.18.4.0/24',
    '71.18.5.0/24',   '71.18.6.0/24',   '71.18.7.0/24',   '71.18.8.0/24',
    '71.18.10.0/24',  '71.18.11.0/24',  '71.18.12.0/24',  '71.18.13.0/24',
    '71.18.16.0/22',  '71.18.20.0/24',  '71.18.21.0/24',  '71.18.24.0/24',
    '71.18.25.0/24',  '71.18.26.0/24',  '71.18.29.0/24',  '71.18.30.0/24',
    '71.18.31.0/24',  '71.18.32.0/24',  '71.18.33.0/24',  '71.18.34.0/24',
    '71.18.35.0/24',  '71.18.36.0/23',  '71.18.38.0/24',  '71.18.39.0/24',
    '71.18.41.0/24',  '71.18.42.0/24',  '71.18.43.0/24',  '71.18.44.0/23',
    '71.18.46.0/24',  '71.18.47.0/24',  '71.18.48.0/23',  '71.18.50.0/24',
    '71.18.51.0/24',  '71.18.52.0/24',  '71.18.53.0/24',  '71.18.54.0/24',
    '71.18.55.0/24',  '71.18.56.0/22',  '71.18.60.0/24',  '71.18.64.0/21',
    '71.18.71.0/24',  '71.18.72.0/24',  '71.18.73.0/24',  '71.18.74.0/24',
    '71.18.75.0/24',  '71.18.77.0/24',  '71.18.79.0/24',  '71.18.80.0/24',
    '71.18.81.0/24',  '71.18.82.0/24',  '71.18.84.0/22',  '71.18.88.0/23',
    '71.18.90.0/23',  '71.18.92.0/24',  '71.18.93.0/24',  '71.18.94.0/24',
    '71.18.95.0/24',  '71.18.96.0/22',  '71.18.100.0/24', '71.18.101.0/24',
    '71.18.102.0/24', '71.18.103.0/24', '71.18.104.0/24', '71.18.105.0/24',
    '71.18.106.0/24', '71.18.107.0/24', '71.18.108.0/22', '71.18.112.0/24',
    '71.18.113.0/24', '71.18.116.0/24', '71.18.117.0/24', '71.18.118.0/24',
    '71.18.119.0/24', '71.18.120.0/23', '71.18.122.0/24', '71.18.123.0/24',
    '71.18.124.0/24', '71.18.125.0/24', '71.18.126.0/24', '71.18.127.0/24',
    '71.18.128.0/24', '71.18.129.0/24', '71.18.130.0/24', '71.18.131.0/24',
    '71.18.132.0/24', '71.18.133.0/24', '71.18.134.0/24', '71.18.135.0/24',
    '71.18.136.0/24', '71.18.137.0/24', '71.18.138.0/24', '71.18.139.0/24',
    '71.18.140.0/22', '71.18.144.0/24', '71.18.145.0/24', '71.18.146.0/24',
    '71.18.147.0/24', '71.18.148.0/24', '71.18.149.0/24', '71.18.150.0/24',
    '71.18.152.0/24', '71.18.153.0/24', '71.18.154.0/24', '71.18.155.0/24',
    '71.18.156.0/24', '71.18.157.0/24', '71.18.158.0/24', '71.18.159.0/24',
    '71.18.160.0/24', '71.18.161.0/24', '71.18.162.0/24', '71.18.163.0/24',
    '71.18.164.0/24', '71.18.165.0/24', '71.18.166.0/24', '71.18.167.0/24',
    '71.18.168.0/24', '71.18.169.0/24', '71.18.170.0/24', '71.18.171.0/24',
    '71.18.175.0/24', '71.18.176.0/24', '71.18.177.0/24', '71.18.178.0/24',
    '71.18.179.0/24', '71.18.180.0/24', '71.18.182.0/24', '71.18.183.0/24',
    '71.18.184.0/24', '71.18.185.0/24', '71.18.186.0/24', '71.18.187.0/24',
    '71.18.188.0/24', '71.18.191.0/24', '71.18.192.0/24', '71.18.193.0/24',
    '71.18.196.0/24', '71.18.197.0/24', '71.18.199.0/24', '71.18.200.0/24',
    '71.18.201.0/24', '71.18.202.0/24', '71.18.203.0/24', '71.18.204.0/24',
    '71.18.205.0/24', '71.18.206.0/24', '71.18.207.0/24', '71.18.208.0/24',
    '71.18.209.0/24', '71.18.210.0/24', '71.18.211.0/24', '71.18.212.0/24',
    '71.18.213.0/24', '71.18.214.0/24', '71.18.215.0/24', '71.18.216.0/24',
    '71.18.217.0/24', '71.18.218.0/24', '71.18.219.0/24', '71.18.222.0/24',
    '71.18.223.0/24', '71.18.224.0/24', '71.18.228.0/24', '71.18.231.0/24',
    '71.18.232.0/24', '71.18.233.0/24', '71.18.237.0/24', '71.18.238.0/24',
    '71.18.239.0/24', '71.18.240.0/24', '71.18.241.0/24', '71.18.243.0/24',
    '71.18.244.0/24', '71.18.245.0/24', '71.18.246.0/24', '71.18.247.0/24',
    '71.18.248.0/24', '71.18.249.0/24', '71.18.250.0/24', '71.18.251.0/24',
    '71.18.252.0/24', '71.18.253.0/24', '71.18.255.0/24',
    '101.45.0.0/24',  '101.45.3.0/24',  '101.45.4.0/24',  '101.45.5.0/24',
    '101.45.14.0/24', '101.45.16.0/24', '101.45.18.0/24', '101.45.192.0/24',
    '101.45.193.0/24','101.45.194.0/24','101.45.195.0/24','101.45.196.0/24',
    '101.45.200.0/23','101.45.248.0/22',
    '103.136.220.0/23','103.136.223.0/24',
    '130.44.212.0/24', '130.44.214.0/24', '130.44.215.0/24',
    '139.177.225.0/24','139.177.227.0/24','139.177.233.0/24','139.177.235.0/24',
    '139.177.238.0/24','139.177.240.0/24','139.177.241.0/24','139.177.242.0/24',
    '139.177.243.0/24','139.177.244.0/24','139.177.245.0/24','139.177.246.0/24',
    '139.177.247.0/24','139.177.248.0/24',
    '147.160.176.0/24','147.160.177.0/24','147.160.180.0/24','147.160.182.0/24',
    '147.160.184.0/24','147.160.190.0/24',
    '180.240.234.0/24','180.240.235.0/24',
    '192.64.15.0/24',
    '199.103.24.0/24', '199.103.25.0/24',
    '202.52.240.0/21',
]

TIKTOK_DOMAINS = [
    'tiktok.com',
    'tiktokcdn.com',
    'tiktokv.com',
    'tiktokcdn-us.com',
    'tiktokapis.com',
    'tiktokstaticb.com',
    'ttlstatic.com',
    'ttwstatic.com',
    'musically.com',
    'byteoversea.com',
    'ibyteimg.com',
    'ibytedtos.com',
]

def _ip_addr_objs():
    return [{'ip_or_subnet': cidr, 'ip_version': 'v4', 'port_ranges': [], 'ports': []}
            for cidr in TIKTOK_IP_RANGES]

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
            raw = r.read()
            return json.loads(raw) if raw.strip() else {}

    def _rules_path(self):
        return f'/proxy/network/v2/api/site/{self.site}/trafficrules'

    def list_rules(self):
        resp = self._req('GET', self._rules_path())
        return resp.get('data', resp) if isinstance(resp, dict) else resp

    def find_rule(self, name):
        for r in self.list_rules():
            if r.get('description', '').lower() == name.lower():
                return r
        return None

    def ensure_rule(self, name):
        """Return existing IP-block rule, creating it (disabled) if absent."""
        rule = self.find_rule(name)
        if rule:
            return rule
        return self._req('POST', self._rules_path(), {
            'action':          'BLOCK',
            'description':     name,
            'enabled':         False,
            'ip_version':      'IPV4',
            'matching_target': 'IP',
            'target_devices':  [{'type': 'ALL_CLIENTS'}],
            'schedule':        {'mode': 'ALWAYS'},
            'app_category_ids': [], 'app_ids': [],
            'network_ids': [], 'regions': [],
            'domains': [], 'ip_ranges': [],
            'ip_addresses': _ip_addr_objs(),
            'bandwidth_limit': {'enabled': False,
                                'download_limit_kbps': 1024,
                                'upload_limit_kbps': 1024},
        })

    def set_enabled(self, rule, enabled: bool):
        r = dict(rule)
        r['enabled'] = enabled
        # Keep ip_addresses current whenever we enable
        if enabled:
            r['ip_addresses'] = _ip_addr_objs()
        return self._req('PUT', f'{self._rules_path()}/{r["_id"]}', r)


# ── Pi-hole client ────────────────────────────────────────────────────────────
class PiHoleClient:
    def __init__(self, host, password):
        self._base = f'http://{host}'
        self._password = password
        self._sid = None

    def _auth(self):
        req = urllib.request.Request(
            f'{self._base}/api/auth',
            data=json.dumps({'password': self._password}).encode(),
            method='POST',
            headers={'Content-Type': 'application/json'},
        )
        with urllib.request.urlopen(req) as r:
            body = json.loads(r.read())
        self._sid = body['session']['sid']

    def _req(self, method, path, body=None):
        if not self._sid:
            self._auth()
        data = json.dumps(body).encode() if body is not None else None
        req  = urllib.request.Request(
            f'{self._base}{path}', data=data, method=method,
            headers={'Content-Type': 'application/json', 'X-FTL-SID': self._sid},
        )
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self._sid = None
                self._auth()
                req.add_header('X-FTL-SID', self._sid)
                with urllib.request.urlopen(req) as r:
                    raw = r.read()
                    return json.loads(raw) if raw.strip() else {}
            raise

    def block(self, domains):
        for domain in domains:
            try:
                self._req('POST', '/api/domains/deny/exact', {
                    'domain':  domain,
                    'comment': 'bad_parents',
                    'groups':  [0],
                    'enabled': True,
                })
            except urllib.error.HTTPError as e:
                if e.code != 409:  # 409 = already exists, that's fine
                    raise

    def unblock(self, domains):
        for domain in domains:
            try:
                self._req('DELETE', f'/api/domains/deny/exact/{domain}')
            except urllib.error.HTTPError as e:
                if e.code != 404:  # 404 = wasn't there, that's fine
                    raise


# ── Block / unblock ───────────────────────────────────────────────────────────
def _make_client():
    c = cfg()
    return UniFiClient(c['controller_url'], c['api_key'], c.get('site', 'default'))


def _make_pihole():
    c = cfg()
    if 'pihole_host' in c and 'pihole_password' in c:
        return PiHoleClient(c['pihole_host'], c['pihole_password'])
    return None


def _do_unblock():
    with _lock:
        try:
            c      = cfg()
            client = _make_client()
            rule   = client.find_rule(c['rule_name'])
            if rule:
                client.set_enabled(rule, False)
            pihole = _make_pihole()
            if pihole:
                pihole.unblock(TIKTOK_DOMAINS)
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
            pihole = _make_pihole()
            if pihole:
                pihole.block(TIKTOK_DOMAINS)
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
