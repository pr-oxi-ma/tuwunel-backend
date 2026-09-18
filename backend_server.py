import email
from email.policy import default
import hmac
import http.client
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import threading
import time
import urllib.parse
import urllib.request

PORT = int(os.environ.get('PORT', 10000))
DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build', 'web')

CONDUIT_HOST = os.environ.get('CONDUIT_HOST', '127.0.0.1')
CONDUIT_PORT = int(os.environ.get('CONDUIT_PORT', 6167))

TOKEN_USER_MAP = {}  # access_token -> user_id
USER_TOKEN_MAP = {}  # user_id -> access_token

EMAIL_MAP_FILES = [
    '/var/lib/tuwunel/email_users.json',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'email_users.json'),
]
EMAIL_USER_MAP = {}
SID_EMAIL_MAP = {}
LAST_REQUESTED_EMAILS = {}
LAST_REGISTER_EMAIL = None

# Secure Verification Code (OTP) Storage & Anti-Abuse
OTP_STORE = {}        # email -> {code, sid, client_secret, token, attempts, max_attempts, expires_at, created_at, validated}
OTP_BY_SID = {}       # sid -> email
EMAIL_COOLDOWNS = {}  # email -> last request timestamp (15s cooldown)
EMAIL_PURPOSE = {}    # email -> 'register' or 'reset_password'

def load_email_map():
    global EMAIL_USER_MAP
    for p in EMAIL_MAP_FILES:
        if os.path.exists(p):
            try:
                with open(p, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        EMAIL_USER_MAP.update(data)
            except Exception as e:
                print(f"[Email Map] Error reading {p}: {e}", flush=True)

def save_email_map():
    for p in EMAIL_MAP_FILES:
        try:
            d = os.path.dirname(p)
            if os.path.exists(d):
                with open(p, 'w') as f:
                    json.dump(EMAIL_USER_MAP, f, indent=2)
        except Exception as e:
            print(f"[Email Map] Error writing to {p}: {e}", flush=True)

load_email_map()

MIME_MAP = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.wasm': 'application/wasm',
    '.json': 'application/json; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.ttf': 'font/ttf',
    '.otf': 'font/otf',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
}

def resolve_token_user(token):
    if not token:
        return None
    if token in TOKEN_USER_MAP:
        uid = TOKEN_USER_MAP[token]
        USER_TOKEN_MAP[uid] = token
        return uid
    try:
        conn = http.client.HTTPConnection(CONDUIT_HOST, CONDUIT_PORT, timeout=5)
        conn.request('GET', '/_matrix/client/v3/account/whoami', headers={'Authorization': f'Bearer {token}'})
        r = conn.getresponse()
        if r.status == 200:
            data = json.loads(r.read().decode('utf-8'))
            uid = data.get('user_id')
            if uid:
                TOKEN_USER_MAP[token] = uid
                USER_TOKEN_MAP[uid] = token
                return uid
        conn.close()
    except Exception:
        pass
    return None

class FastCachedHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def _is_matrix_request(self):
        parsed = urllib.parse.urlparse(self.path)
        p = parsed.path
        return p.startswith('/_matrix') or p.startswith('/.well-known/matrix') or p.startswith('/_tuwunel')

    def _proxy_to_conduit(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            # Intercept well-known to always dynamically return the current URL
            if path in ('/.well-known/matrix/client', '/.well-known/matrix/support', '/.well-known/matrix/server'):
                host_hdr = self.headers.get('Host', '')
                scheme = 'https' if ('trycloudflare.com' in host_hdr or self.headers.get('X-Forwarded-Proto') == 'https') else 'http'
                base_url = f"{scheme}://{host_hdr}/" if host_hdr else "http://127.0.0.1:8080/"

                if path == '/.well-known/matrix/client':
                    resp_data = {"m.homeserver": {"base_url": base_url}}
                elif path == '/.well-known/matrix/support':
                    resp_data = {
                        "contacts": [
                            {
                                "email_address": "support@tuwunel.chat",
                                "role": "m.role.admin"
                            }
                        ],
                        "support_page": base_url
                    }
                else:
                    server_target = host_hdr if host_hdr else "127.0.0.1:8080"
                    if ':443' not in server_target and not server_target.startswith('127.0.0.1') and not server_target.startswith('localhost'):
                        server_target = f"{server_target}:443"
                    resp_data = {"m.server": server_target}

                resp_body = json.dumps(resp_data).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(resp_body)))
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(resp_body)
                return


            # Intercept submitCode (verify 6-digit OTP code)
            if self.command == 'POST' and path in (
                '/_matrix/client/v3/register/email/submitCode',
                '/_matrix/client/v3/account/password/email/submitCode',
                '/_tuwunel/3pid/email/submitCode'
            ):
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                    em = data.get('email', '').strip().lower()
                    code_in = str(data.get('code', '')).strip()
                    sid_in = data.get('sid', '').strip()

                    entry = OTP_STORE.get(em)
                    if not entry and sid_in in OTP_BY_SID:
                        entry = OTP_STORE.get(OTP_BY_SID[sid_in])

                    if not entry:
                        resp_data = {"errcode": "M_NOT_FOUND", "error": "No pending verification found for this email. Please request a code."}
                        resp_code = 400
                    elif entry.get('validated'):
                        resp_data = {"success": True, "message": "Email already verified", "sid": entry['sid'], "client_secret": entry['client_secret']}
                        resp_code = 200
                    elif time.time() > entry.get('expires_at', 0):
                        resp_data = {"errcode": "M_EXPIRED", "error": "Verification code has expired. Please tap 'Resend Code'."}
                        resp_code = 400
                    elif entry.get('attempts', 0) >= entry.get('max_attempts', 5):
                        resp_data = {"errcode": "M_TOO_MANY_ATTEMPTS", "error": "Maximum attempts exceeded. Please request a new code."}
                        resp_code = 429
                    else:
                        entry['attempts'] += 1
                        if not hmac.compare_digest(code_in, entry.get('code', '')):
                            rem = entry['max_attempts'] - entry['attempts']
                            resp_data = {"errcode": "M_INVALID_CODE", "error": f"Incorrect code. {rem} attempt(s) remaining."}
                            resp_code = 400
                        else:
                            # Code matches! Validate with Tuwunel backend
                            post_data = urllib.parse.urlencode({
                                'sid': entry['sid'],
                                'client_secret': entry['client_secret'],
                                'token': entry['token']
                            }).encode('utf-8')
                            v_conn = http.client.HTTPConnection(CONDUIT_HOST, CONDUIT_PORT, timeout=5)
                            v_headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Connection': 'close'}
                            v_conn.request('POST', '/_tuwunel/3pid/email/validate', body=post_data, headers=v_headers)
                            v_res = v_conn.getresponse()
                            v_res.read()
                            v_conn.close()

                            entry['validated'] = True
                            print(f"[OTP Verify] Successfully verified code {code_in} for {em} (sid: {entry['sid']})", flush=True)
                            resp_data = {
                                "success": True,
                                "message": "Email verified successfully!",
                                "sid": entry['sid'],
                                "client_secret": entry['client_secret']
                            }
                            resp_code = 200
                except Exception as ex:
                    print(f"[OTP Verify] Exception: {ex}", flush=True)
                    resp_data = {"errcode": "M_UNKNOWN", "error": f"Verification error: {str(ex)}"}
                    resp_code = 500

                resp_bytes = json.dumps(resp_data).encode('utf-8')
                self.send_response(resp_code)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(resp_bytes)))
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(resp_bytes)
                return

            # Intercept checkStatus (poll if verified via email link or code)
            if self.command == 'POST' and path in (
                '/_matrix/client/v3/register/email/checkStatus',
                '/_matrix/client/v3/account/password/email/checkStatus',
                '/_tuwunel/3pid/email/checkStatus'
            ):
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                    em = data.get('email', '').strip().lower()
                    sid_in = data.get('sid', '').strip()
                    entry = OTP_STORE.get(em)
                    if not entry and sid_in in OTP_BY_SID:
                        entry = OTP_STORE.get(OTP_BY_SID[sid_in])
                    is_val = bool(entry and entry.get('validated'))
                    resp_data = {"validated": is_val}
                except Exception:
                    resp_data = {"validated": False}

                resp_bytes = json.dumps(resp_data).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(resp_bytes)))
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(resp_bytes)
                return

            # If user opens the email verification link in browser, auto-validate immediately!
            if self.command == 'GET' and '/_tuwunel/3pid/email/validate' in path:
                query_params = urllib.parse.parse_qs(parsed.query)
                v_sid = query_params.get('sid', [None])[0]
                v_sec = query_params.get('client_secret', [None])[0]
                v_tok = query_params.get('token', [None])[0]
                if v_sid and v_sec and v_tok:
                    try:
                        post_data = urllib.parse.urlencode({
                            'sid': v_sid,
                            'client_secret': v_sec,
                            'token': v_tok
                        }).encode('utf-8')
                        v_conn = http.client.HTTPConnection(CONDUIT_HOST, CONDUIT_PORT, timeout=5)
                        v_headers = {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Connection': 'close'
                        }
                        v_conn.request('POST', '/_tuwunel/3pid/email/validate', body=post_data, headers=v_headers)
                        v_res = v_conn.getresponse()
                        v_res.read()
                        v_conn.close()

                        if v_sid in OTP_BY_SID:
                            clean_em = OTP_BY_SID[v_sid]
                            if clean_em in OTP_STORE:
                                OTP_STORE[clean_em]['validated'] = True

                        print(f"[Email Auto-Validate] Auto-validated token for sid={v_sid}", flush=True)
                    except Exception as e:
                        print(f"[Email Auto-Validate] Error: {e}", flush=True)

                    success_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Email Verified - FluffyChat</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f8fafc; color: #0f172a; }
        .card { background: #ffffff; border: 1px solid #e2e8f0; padding: 2.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); text-align: center; max-width: 420px; }
        h1 { margin: 0 0 0.5rem 0; font-size: 1.35rem; color: #0f172a; font-weight: 600; letter-spacing: -0.3px; }
        p { color: #475569; line-height: 1.5; font-size: 0.95rem; margin: 0; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Email Verified</h1>
        <p>Your email address has been successfully verified.<br>You can now return to the app to continue.</p>
    </div>
</body>
</html>""".encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Content-Length', str(len(success_html)))
                    self._send_security_headers()
                    self.end_headers()
                    self.wfile.write(success_html)
                    return

            timeout = 120 if '/sync' in path else 30
            conn = http.client.HTTPConnection(CONDUIT_HOST, CONDUIT_PORT, timeout=timeout)
            headers = {}
            for k, v in self.headers.items():
                if k.lower() not in ('host', 'transfer-encoding', 'connection', 'accept-encoding'):
                    headers[k] = v
            headers['Host'] = f'{CONDUIT_HOST}:{CONDUIT_PORT}'

            # Intercept requestToken to track sid -> email and enforce rate limiting (15s cooldown)
            req_email = None
            req_sec = None
            is_reg_token = ('/register/email/requestToken' in path)
            is_pwd_token = ('/account/password/email/requestToken' in path)
            if (is_reg_token or is_pwd_token) and body and self.command == 'POST':
                try:
                    rt_req = json.loads(body.decode('utf-8'))
                    req_email = rt_req.get('email', '').strip().lower()
                    req_sec = rt_req.get('client_secret', '')
                    if req_email:
                        now = time.time()
                        last_t = EMAIL_COOLDOWNS.get(req_email, 0)
                        if (now - last_t) < 15:
                            rem = int(15 - (now - last_t))
                            resp_bytes = json.dumps({
                                "errcode": "M_LIMIT_EXCEEDED",
                                "error": f"Please wait {rem}s before requesting another verification code."
                            }).encode('utf-8')
                            self.send_response(429)
                            self.send_header('Content-Type', 'application/json; charset=utf-8')
                            self.send_header('Content-Length', str(len(resp_bytes)))
                            self._send_security_headers()
                            self.end_headers()
                            self.wfile.write(resp_bytes)
                            return
                        EMAIL_COOLDOWNS[req_email] = now
                        if is_pwd_token:
                            EMAIL_PURPOSE[req_email] = 'reset_password'
                        else:
                            EMAIL_PURPOSE[req_email] = 'register'
                        LAST_REGISTER_EMAIL = req_email
                        if req_sec:
                            LAST_REQUESTED_EMAILS[req_sec] = req_email
                except Exception as ex:
                    print(f"[Email Token Req] Error parsing: {ex}", flush=True)

            # Intercept login to resolve email -> username for Tuwunel
            if path.endswith('/login') and self.command == 'POST' and body:
                try:
                    login_data = json.loads(body.decode('utf-8'))
                    ident = login_data.get('identifier', {})
                    target_email = None
                    if isinstance(ident, dict):
                        if ident.get('type') == 'm.id.thirdparty' and ident.get('medium') == 'email':
                            target_email = ident.get('address', '').strip().lower()
                        elif ident.get('type') == 'm.id.user':
                            u_str = str(ident.get('user', '')).strip()
                            if '@' in u_str and not u_str.startswith('@') and ':' not in u_str:
                                target_email = u_str.lower()
                    elif 'user' in login_data:
                        u_str = str(login_data['user']).strip()
                        if '@' in u_str and not u_str.startswith('@') and ':' not in u_str:
                            target_email = u_str.lower()

                    if target_email:
                        load_email_map()
                        mapped_user = EMAIL_USER_MAP.get(target_email)
                        if not mapped_user:
                            mapped_user = target_email.split('@')[0]
                            print(f"[Email Login Resolution] Unmapped email {target_email}, falling back to prefix: {mapped_user}", flush=True)
                        else:
                            print(f"[Email Login Resolution] Resolved verified email {target_email} -> {mapped_user}", flush=True)

                        if mapped_user:
                            login_data['identifier'] = {
                                "type": "m.id.user",
                                "user": mapped_user
                            }
                            login_data['user'] = mapped_user
                            body = json.dumps(login_data).encode('utf-8')
                            headers['Content-Length'] = str(len(body))
                except Exception as ex:
                    print(f"[Email Login Resolution] Error: {ex}", flush=True)

            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            conn.close()

            # If registration failed with stale/non-existent UIAA session, retry once without session!
            if path.endswith('/register') and resp.status == 403 and b'UIAA session does not exist' in resp_body and body:
                try:
                    retry_data = json.loads(body.decode('utf-8'))
                    if 'auth' in retry_data and 'session' in retry_data['auth']:
                        del retry_data['auth']['session']
                        retry_bytes = json.dumps(retry_data).encode('utf-8')
                        headers['Content-Length'] = str(len(retry_bytes))
                        r_conn = http.client.HTTPConnection(CONDUIT_HOST, CONDUIT_PORT, timeout=timeout)
                        r_conn.request(self.command, self.path, body=retry_bytes, headers=headers)
                        resp = r_conn.getresponse()
                        resp_body = resp.read()
                        r_conn.close()
                        body = retry_bytes
                        print(f"[Register Retry] Retried without stale session: status {resp.status}", flush=True)
                except Exception as ex:
                    print(f"[Register Retry] Error retrying registration: {ex}", flush=True)

            # If requestToken response 200, map sid -> email
            if ('/register/email/requestToken' in path or '/account/password/email/requestToken' in path) and resp.status == 200:
                try:
                    rt_resp = json.loads(resp_body.decode('utf-8'))
                    sid = rt_resp.get('sid')
                    if sid and req_email:
                        SID_EMAIL_MAP[sid] = req_email
                        print(f"[Email Token] Mapped sid {sid} -> {req_email}", flush=True)
                except Exception:
                    pass

            # If register response 200, map email -> username
            if path.endswith('/register') and resp.status == 200 and body:
                try:
                    reg_req = json.loads(body.decode('utf-8'))
                    res_json = json.loads(resp_body.decode('utf-8'))
                    uid = res_json.get('user_id', '')
                    uname = None
                    if uid and '@' in uid:
                        uname = uid.split(':')[0].lstrip('@')
                    if not uname:
                        uname = reg_req.get('username')

                    auth_obj = reg_req.get('auth', {})
                    sid = auth_obj.get('threepid_creds', {}).get('sid') or auth_obj.get('threepidCreds', {}).get('sid')
                    sec = auth_obj.get('threepid_creds', {}).get('client_secret') or auth_obj.get('threepidCreds', {}).get('clientSecret')

                    em = SID_EMAIL_MAP.get(sid) or LAST_REQUESTED_EMAILS.get(sec) or LAST_REGISTER_EMAIL
                    if em and uname:
                        em = em.strip().lower()
                        EMAIL_USER_MAP[em] = uname
                        save_email_map()
                        print(f"[Email Map] Successfully registered and mapped email {em} -> username {uname} (UID: {uid})", flush=True)
                except Exception as ex:
                    print(f"[Email Map] Error mapping register: {ex}", flush=True)

            # If login/register, log request and response for diagnostics
            if '/login' in path or '/register' in path:
                try:
                    print(f"[DEBUG LOG] {path} request: {body.decode('utf-8') if body else None}", flush=True)
                    print(f"[DEBUG LOG] {path} response {resp.status}: {resp_body.decode('utf-8')}", flush=True)
                except Exception as ex:
                    print(f"[DEBUG LOG] error printing: {ex}", flush=True)

            # If login successful, map token to user_id
            if resp.status == 200 and ('/login' in path or '/register' in path):
                try:
                    res_json = json.loads(resp_body.decode('utf-8'))
                    tok = res_json.get("access_token")
                    uid = res_json.get("user_id")
                    if tok and uid:
                        TOKEN_USER_MAP[tok] = uid
                        USER_TOKEN_MAP[uid] = tok
                except Exception:
                    pass

            # Filter user directory search results to remove test/system users
            if '/user_directory/search' in path and resp.status == 200:
                try:
                    ud_data = json.loads(resp_body.decode('utf-8'))
                    BLOCKED_USERS = {'conduit', 'adnandev', 'adnanvip', 'executivetest', 'sarahdev', 'securityuser'}
                    filtered = []
                    for item in ud_data.get('results', []):
                        uid = item.get('user_id', '')
                        localpart = uid.split(':')[0].lstrip('@').lower()
                        if localpart not in BLOCKED_USERS:
                            filtered.append(item)
                    ud_data['results'] = filtered
                    resp_body = json.dumps(ud_data).encode('utf-8')
                except Exception as ex:
                    print(f"[User Dir Filter] Error: {ex}", flush=True)

            self.send_response(resp.status)
            sent_headers = set()
            for k, v in resp.getheaders():
                kl = k.lower()
                if kl not in ('server', 'date', 'transfer-encoding', 'connection', 'content-length'):
                    self.send_header(k, v)
                    sent_headers.add(kl)
            self.send_header('Content-Length', str(len(resp_body)))
            if 'access-control-allow-origin' not in sent_headers:
                self.send_header('Access-Control-Allow-Origin', '*')
            if 'access-control-allow-methods' not in sent_headers:
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            if 'access-control-allow-headers' not in sent_headers:
                self.send_header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization')
            if 'cross-origin-opener-policy' not in sent_headers:
                self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
            if 'cross-origin-embedder-policy' not in sent_headers:
                self.send_header('Cross-Origin-Embedder-Policy', 'credentialless')
            self.end_headers()

            self.wfile.write(resp_body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                print(f"[Proxy Error] {self.command} {self.path}: {e}", flush=True)
                self.send_response(502)
                self._send_security_headers()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                err = f'{{"errcode":"M_UNKNOWN","error":"Conduit Gateway Proxy Error: {str(e)}"}}'
                self.wfile.write(err.encode('utf-8'))
            except Exception:
                pass

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_security_headers()
        self.end_headers()

    def do_GET(self):
        if self._is_matrix_request():
            self._proxy_to_conduit()
        else:
            self._handle_request(is_head=False)

    def do_HEAD(self):
        if self._is_matrix_request():
            self._proxy_to_conduit()
        else:
            self._handle_request(is_head=True)

    def do_POST(self):
        if self._is_matrix_request():
            self._proxy_to_conduit()
        else:
            self.send_error(405, "Method not allowed")

    def do_PUT(self):
        if self._is_matrix_request():
            self._proxy_to_conduit()
        else:
            self.send_error(405, "Method not allowed")

    def do_DELETE(self):
        if self._is_matrix_request():
            self._proxy_to_conduit()
        else:
            self.send_error(405, "Method not allowed")

    def _handle_request(self, is_head=False):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.strip('/')
        if not path:
            path = 'index.html'

        if path in ('healthz', 'health', '_health'):
            self.send_response(200)
            self._send_security_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok","service":"tuwunel-backend"}')
            return

        full_path = os.path.join(DIRECTORY, path)

        # NEVER return index.html for API paths or unknown extension-less routes
        if not os.path.exists(full_path):
            if path in ('index.html', ''):
                self.send_response(200)
                self._send_security_headers()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status":"ok","service":"tuwunel-matrix-backend"}')
                return
            if path.startswith('_matrix') or path.startswith('.well-known'):
                self.send_response(404)
                self._send_security_headers()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"errcode":"M_NOT_FOUND","error":"Endpoint not found"}')
                return
            if not os.path.splitext(path)[1]:
                full_path = os.path.join(DIRECTORY, 'index.html')
                path = 'index.html'

        if path in ('config.json', 'assets/config.json'):
            host = self.headers.get('Host', '').split(':')[0] or '127.0.0.1'
            config_data = {
                "applicationName": "FluffyChat",
                "defaultHomeserver": host,
                "presetHomeserver": host,
                "welcomeText": "Simple, secure & privacy-first messaging",
                "sendTypingNotifications": True,
                "sendPublicReadReceipts": True,
                "shareOnlineStatus": True,
                "showPresences": True,
                "shareKeysWith": "all",
                "noEncryptionWarningShown": False,
                "enableSoftLogout": False,
                "doubleTapToReact": True
            }
            body = json.dumps(config_data).encode('utf-8')
            self.send_response(200)
            self._send_security_headers()
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-cache, must-revalidate')
            self.end_headers()
            self.wfile.write(body)
            return

        if not os.path.exists(full_path) or os.path.isdir(full_path):
            self.send_error(404, "File not found")
            return

        stat = os.stat(full_path)
        fsize = stat.st_size
        mtime = int(stat.st_mtime)
        etag = f'"{mtime}-{fsize}"'

        is_revalidate = (
            path in ('index.html', 'config.json', 'version.json', 'flutter_service_worker.js')
        )

        client_etag = self.headers.get('If-None-Match')
        if client_etag == etag:
            self.send_response(304)
            self.send_header('ETag', etag)
            if is_revalidate:
                self.send_header('Cache-Control', 'no-cache, must-revalidate')
            else:
                self.send_header('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400')
            self._send_security_headers()
            self.end_headers()
            return

        accept_encoding = self.headers.get('Accept-Encoding', '')
        supports_gzip = 'gzip' in accept_encoding

        gz_path = full_path + '.gz'
        use_gzip = supports_gzip and os.path.exists(gz_path)

        send_path = gz_path if use_gzip else full_path
        send_size = os.path.getsize(send_path)

        _, ext = os.path.splitext(full_path)
        content_type = MIME_MAP.get(ext.lower(), self.guess_type(full_path))

        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(send_size))
        self.send_header('ETag', etag)
        self.send_header('Vary', 'Accept-Encoding')

        if is_revalidate:
            self.send_header('Cache-Control', 'no-cache, must-revalidate')
        else:
            self.send_header('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400')

        if use_gzip:
            self.send_header('Content-Encoding', 'gzip')

        self._send_security_headers()
        self.end_headers()

        if not is_head:
            with open(send_path, 'rb') as f:
                self.copyfile(f, self.wfile)

    def _send_security_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'credentialless')

VERCEL_MAILER_URL = os.environ.get("VERCEL_MAILER_URL", "https://ig-mailer.vercel.app/api/send-email")
VERCEL_MAILER_SECRET = os.environ.get("VERCEL_MAILER_SECRET", "lnCT2j26UCFKY7CeGLkhjVh70lJu0bdO5e5Rxa0za3aMq6ucNmPKU4SKlDaxDf84dpRxvgqUmrW9YKCloXV+Jg==")

RENDER_HOST = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
DEFAULT_BASE = f"https://{RENDER_HOST}" if RENDER_HOST else "https://tuwunel-matrix.onrender.com"
ACTIVE_PUBLIC_BASE = os.environ.get("ACTIVE_PUBLIC_BASE", DEFAULT_BASE)


def forward_to_vercel(to_addr, subject, text_body, html_body):
    clean_addr = to_addr.strip().lower()

    # Normalize encoded characters in email body to accurately parse token
    combined = (text_body + " " + html_body).replace("=\n", "").replace("=\r\n", "").replace("3D", "=").replace("&amp;", "&")

    m = re.search(r'/_tuwunel/3pid/email/validate\?sid=([a-zA-Z0-9_-]+)&client_secret=([a-zA-Z0-9_-]+)&token=([a-zA-Z0-9_-]+)', combined)

    otp_code = None
    val_link = ""
    if m:
        sid = m.group(1)
        client_sec = m.group(2)
        tok = m.group(3)

        # Generate cryptographically secure 6-digit OTP code
        otp_code = f"{secrets.randbelow(900000) + 100000}"

        OTP_STORE[clean_addr] = {
            "code": otp_code,
            "sid": sid,
            "client_secret": client_sec,
            "token": tok,
            "attempts": 0,
            "max_attempts": 5,
            "expires_at": time.time() + 600,  # 10 minutes
            "created_at": time.time(),
            "validated": False
        }
        OTP_BY_SID[sid] = clean_addr
        val_link = f"{ACTIVE_PUBLIC_BASE}/_tuwunel/3pid/email/validate?sid={sid}&client_secret={client_sec}&token={tok}"
        print(f"[OTP Bridge] Generated secure code {otp_code} for {clean_addr} (sid: {sid})", flush=True)

    if otp_code:
        purpose = EMAIL_PURPOSE.get(clean_addr, 'register')
        if 'password' in (subject or '').lower() or 'password' in (text_body or '').lower():
            purpose = 'reset_password'

        if purpose == 'reset_password':
            subject = f"{otp_code} is your FluffyChat password reset code"
            heading = "Reset your password"
            intro = "We received a request to reset the password for your FluffyChat account. Please enter the verification code below to set a new password:"
            expiry_text = "This code will expire in 10 minutes and can only be used once."
            action_button = ""
            footnote = "If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged."
            text_body = f"""Hello,

We received a request to reset the password for your FluffyChat account.

Your verification code is:
{otp_code}

This code will expire in 10 minutes and can only be used once.

If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged.

FluffyChat Security Team
"""
        else:
            subject = f"{otp_code} is your FluffyChat verification code"
            heading = "Verify your email address"
            intro = "Thank you for creating an account on FluffyChat. Please enter the verification code below to complete your registration:"
            expiry_text = "This code will expire in 10 minutes and can only be used once."
            action_button = f"""<div style="margin-top: 24px; text-align: center;">
    <a href="{val_link}" target="_blank" style="display: inline-block; padding: 10px 20px; background-color: #0f172a; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 13px; font-weight: 500;">Verify email in browser</a>
</div>""" if val_link else ""
            footnote = "If you did not request this verification code, you can safely ignore this email."
            text_body = f"""Hello,

Your verification code for FluffyChat is:
{otp_code}

This code will expire in 10 minutes and can only be used once. Please enter it in the app to complete your account registration.

Or verify directly in your browser:
{val_link}

If you did not request this verification code, you can safely ignore this email.

FluffyChat Security Team
"""

        html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{subject}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; color: #0f172a;">
    <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f8fafc; padding: 48px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 480px; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05); text-align: left;">
                    <tr>
                        <td style="padding: 32px 32px 0 32px;">
                            <span style="font-size: 18px; font-weight: 700; letter-spacing: -0.5px; color: #0f172a;">FluffyChat</span>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 24px 32px 32px 32px;">
                            <h1 style="font-size: 20px; font-weight: 600; color: #0f172a; margin: 0 0 12px 0; letter-spacing: -0.3px;">{heading}</h1>
                            <p style="font-size: 14px; line-height: 22px; color: #475569; margin: 0 0 24px 0;">
                                {intro}
                            </p>
                            <div style="background-color: #f1f5f9; border: 1px solid #cbd5e1; border-radius: 6px; padding: 18px 24px; text-align: center; margin: 0 0 16px 0;">
                                <div style="font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace; font-size: 36px; font-weight: 700; letter-spacing: 10px; color: #0f172a; padding-left: 10px;">
                                    {otp_code}
                                </div>
                            </div>
                            <p style="font-size: 12px; line-height: 18px; color: #64748b; margin: 0 0 20px 0; text-align: center;">
                                {expiry_text}
                            </p>
                            {action_button}
                            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 28px 0 20px 0;" />
                            <p style="font-size: 12px; line-height: 18px; color: #64748b; margin: 0;">
                                {footnote}
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 32px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;">
                            <p style="font-size: 11px; line-height: 16px; color: #94a3b8; margin: 0;">
                                &copy; 2026 FluffyChat. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""
    else:
        if ACTIVE_PUBLIC_BASE:
            text_body = re.sub(r'https?://[^/]+(/_tuwunel/[^\s">]+)', f'{ACTIVE_PUBLIC_BASE}\\1', text_body)
            html_body = re.sub(r'https?://[^/]+(/_tuwunel/[^\s">]+)', f'{ACTIVE_PUBLIC_BASE}\\1', html_body)

    print(f"[SMTP Bridge] Outgoing email to {to_addr}:\nSubject: {subject}\n", flush=True)
    payload = {
        "to": to_addr,
        "subject": subject or "Matrix Verification",
        "text": text_body or "",
        "html": html_body or f"<p>{text_body}</p>"
    }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        VERCEL_MAILER_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {VERCEL_MAILER_SECRET}",
            "Content-Type": "application/json",
            "User-Agent": "Tuwunel-SMTP-Bridge/1.0"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            res = resp.read().decode('utf-8')
            print(f"[SMTP Bridge] Delivered email to {to_addr} via Vercel: {res}", flush=True)
            return True
    except Exception as e:
        print(f"[SMTP Bridge] Error forwarding email to Vercel for {to_addr}: {e}", flush=True)
        return False

def handle_smtp_client(sock):
    try:
        sock.sendall(b"220 localhost ESMTP Tuwunel-Mailer-Bridge Ready\r\n")
        mail_data = bytearray()
        in_data = False
        rcpt_to = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            if in_data:
                mail_data.extend(data)
                if b"\r\n.\r\n" in mail_data or mail_data.endswith(b"\n.\n") or mail_data.endswith(b"\n.\r\n"):
                    dot_idx = mail_data.rfind(b"\r\n.\r\n")
                    raw = bytes(mail_data[:dot_idx]) if dot_idx != -1 else bytes(mail_data)
                    try:
                        msg = email.message_from_bytes(raw, policy=default)
                        to_hdr = msg['To'] or (rcpt_to[0] if rcpt_to else '')
                        if '<' in to_hdr and '>' in to_hdr:
                            to_hdr = to_hdr.split('<')[1].split('>')[0]
                        to_hdr = to_hdr.strip()
                        subj = msg['Subject'] or 'Verification Code'
                        text_part = raw.decode('utf-8', errors='replace')
                        body_plain = msg.get_body(preferencelist=('plain',))
                        if body_plain:
                            text_part = body_plain.get_content()
                        body_html = msg.get_body(preferencelist=('html',))
                        html_part = body_html.get_content() if body_html else f"<p>{text_part}</p>"

                        recipients = [to_hdr] if to_hdr else rcpt_to
                        for r in recipients:
                            r_clean = r.strip()
                            if '<' in r_clean and '>' in r_clean:
                                r_clean = r_clean.split('<')[1].split('>')[0]
                            if r_clean:
                                threading.Thread(
                                    target=forward_to_vercel,
                                    args=(r_clean, subj, text_part, html_part),
                                    daemon=True
                                ).start()
                    except Exception as ex:
                        print(f"[SMTP Bridge] Parse exception: {ex}", flush=True)

                    sock.sendall(b"250 OK: message queued\r\n")
                    in_data = False
                    mail_data.clear()
                    rcpt_to.clear()
            else:
                line = data.decode('utf-8', errors='ignore').strip()
                up = line.upper()
                if up.startswith("EHLO") or up.startswith("HELO"):
                    sock.sendall(b"250-localhost\r\n250-8BITMIME\r\n250-SIZE 10485760\r\n250 OK\r\n")
                elif up.startswith("MAIL FROM:"):
                    sock.sendall(b"250 OK\r\n")
                elif up.startswith("RCPT TO:"):
                    rcpt = line.split('<')[1].split('>')[0] if '<' in line else line[8:].strip()
                    rcpt_to.append(rcpt)
                    sock.sendall(b"250 OK\r\n")
                elif up == "DATA":
                    in_data = True
                    sock.sendall(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                elif up.startswith("RSET"):
                    rcpt_to.clear()
                    mail_data.clear()
                    in_data = False
                    sock.sendall(b"250 OK\r\n")
                elif up.startswith("NOOP"):
                    sock.sendall(b"250 OK\r\n")
                elif up.startswith("QUIT"):
                    sock.sendall(b"221 Bye\r\n")
                    break
                else:
                    sock.sendall(b"250 OK\r\n")
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

def start_smtp_bridge(host="0.0.0.0", port=2525):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(10)
        print(f"[SMTP Bridge] Listening on {host}:{port} -> Forwarding to {VERCEL_MAILER_URL}", flush=True)
        while True:
            try:
                client_sock, _ = srv.accept()
                threading.Thread(target=handle_smtp_client, args=(client_sock,), daemon=True).start()
            except Exception as e:
                time.sleep(1)
    except Exception as e:
        print(f"[SMTP Bridge] Failed to bind {host}:{port}: {e}", flush=True)

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == '__main__':
    smtp_port = int(os.environ.get('SMTP_PORT', 2525))
    threading.Thread(target=start_smtp_bridge, kwargs={"port": smtp_port}, daemon=True).start()

    port = int(os.environ.get('PORT', PORT))
    with ThreadingTCPServer(("", port), FastCachedHandler) as httpd:
        print(f"Serving Web UI with Matrix reverse proxy from {DIRECTORY} on port {port}...")
        httpd.serve_forever()
