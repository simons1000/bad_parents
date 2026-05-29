#!/usr/bin/env python3
"""
bad_parents — TikTok block controller for UniFi Dream Machine
Toggles a named Traffic Rule via the UniFi OS API.
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

# ── State ─────────────────────────────────────────────────────────────────────
state = {
    'blocked':    False,
    'unblock_at': None,   # epoch seconds
    'error':      None,
}
_timer: threading.Timer | None = None
_lock  = threading.Lock()


# ── Config ────────────────────────────────────────────────────────────────────
def cfg():
    with open(os.path.join(BASE, 'config.json')) as f:
        return json.load(f)


# ── UniFi API client (API-key / Bearer token auth — no 2FA required) ──────────
class UniFiClient:
    def __init__(self, base_url, api_key, site='default'):
        self.base    = base_url.rstrip('/')
        self.site    = site
        self._key    = api_key
        self._ctx    = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode    = ssl.CERT_NONE

    def _req(self, method, path, body=None):
        url  = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req  = urllib.request.Request(url, data=data, method=method, headers={
            'Content-Type':  'application/json',
            'Accept':        'application/json',
            'Authorization': f'Bearer {self._key}',
            'X-API-KEY':     self._key,   # some firmware versions use this header
        })
        ctx = self._ctx
        with urllib.request.urlopen(req, context=ctx) as r:
            return json.loads(r.read())

    def traffic_rules(self):
        return self._req('GET', f'/proxy/network/v2/api/site/{self.site}/trafficrules')

    def set_rule_enabled(self, rule, enabled: bool):
        rule = dict(rule)
        rule['enabled'] = enabled
        return self._req('PUT',
            f'/proxy/network/v2/api/site/{self.site}/trafficrules/{rule["_id"]}',
            rule)


def find_rule(client, name):
    rules = client.traffic_rules()
    for r in (rules if isinstance(rules, list) else rules.get('data', [])):
        if r.get('description', '').lower() == name.lower():
            return r
    return None


# ── Block / unblock logic ─────────────────────────────────────────────────────
def _do_unblock():
    with _lock:
        try:
            c = cfg()
            client = UniFiClient(c['controller_url'], c['api_key'],
                                 c.get('site', 'default'))
            rule = find_rule(client, c['rule_name'])
            if rule:
                client.set_rule_enabled(rule, False)
            state['blocked']    = False
            state['unblock_at'] = None
            state['error']      = None
        except Exception as e:
            state['error'] = str(e)


def block_tiktok():
    global _timer
    with _lock:
        try:
            c = cfg()
            client = UniFiClient(c['controller_url'], c['api_key'],
                                 c.get('site', 'default'))
            rule = find_rule(client, c['rule_name'])
            if not rule:
                state['error'] = (
                    f"No Traffic Rule named \"{c['rule_name']}\" found. "
                    "Create it in UniFi → Traffic Rules first."
                )
                return
            client.set_rule_enabled(rule, True)
            duration = int(c.get('block_minutes', 5)) * 60
            state['blocked']    = True
            state['unblock_at'] = time.time() + duration
            state['error']      = None
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
                'blocked':      state['blocked'],
                'unblock_at':   state['unblock_at'],
                'error':        state['error'],
                'block_minutes': c.get('block_minutes', 5),
                'rule_name':    c.get('rule_name', ''),
            })
        elif self.path == '/api/rules':
            # Helper: list all traffic rules so the user can find the right name
            try:
                c      = cfg()
                client = UniFiClient(c['controller_url'], c['username'],
                                     c['password'], c.get('site', 'default'))
                rules  = client.traffic_rules()
                names  = [r.get('description', '?')
                          for r in (rules if isinstance(rules, list)
                                    else rules.get('data', []))]
                self._json({'rules': names})
            except Exception as e:
                self._json({'error': str(e)}, 502)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/api/block':
            threading.Thread(target=block_tiktok, daemon=True).start()
            time.sleep(0.3)   # let the thread start before responding
            self._json({'ok': True})
        elif self.path == '/api/unblock':
            threading.Thread(target=unblock_tiktok, daemon=True).start()
            time.sleep(0.3)
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
