"""
End-to-end test of the register -> login -> device management -> recovery
flow, plus negative paths (pre-auth session, cross-user access, tampered
signatures, challenge replay, CSRF), using a software authenticator
(virtual_authenticator.py) instead of a real fingerprint/security key. Runs
against a throwaway temp database, never the real securepass.db. No pytest
dependency — plain script, matching tests/smoke_test.py's style.

Run: venv/Scripts/python.exe tests/test_webauthn_flow.py
"""
import base64
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(__file__))

_tmp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
_tmp_db.close()
os.environ['DATABASE_PATH'] = _tmp_db.name
os.environ.setdefault('SECRET_KEY', 'test-secret-key')

from app import app  # noqa: E402  (must import after env vars are set)
from virtual_authenticator import VirtualAuthenticator, b64url, b64url_decode  # noqa: E402

failures = []
total_checks = 0
_client_seq = 0


def new_client():
    """A fresh simulated browser. Each gets its own source IP so one test can't
    spend another's rate-limit budget (the limiter keys on remote address)."""
    global _client_seq
    _client_seq += 1
    c = app.test_client()
    c.environ_base = dict(c.environ_base, REMOTE_ADDR=f'10.0.{_client_seq // 250}.{_client_seq % 250}')
    return c


client = new_client()
authenticator = VirtualAuthenticator()


def check(label, condition):
    global total_checks
    total_checks += 1
    print(f'[{"PASS" if condition else "FAIL"}] {label}')
    if not condition:
        failures.append(label)


def csrf(c):
    """A browser gets the token from the page it loads first."""
    c.get('/login')
    with c.session_transaction() as sess:
        return sess.get('csrf_token', '')


def post(c, url, payload):
    return c.post(url, json=payload, headers={'X-CSRF-Token': csrf(c)})


def delete(c, url):
    return c.delete(url, headers={'X-CSRF-Token': csrf(c)})


def register(c, auth, name, email):
    begin = post(c, '/api/register/begin', {'name': name, 'email': email})
    if begin.status_code != 200:
        return begin
    options = begin.get_json()['publicKey']
    reg = auth.create_credential(options['rp']['id'], options['challenge'], 'http://localhost:5000')
    return post(c, '/api/register/complete', reg)


def login_begin(c, email=None):
    begin = post(c, '/api/login/begin', {'email': email} if email else {})
    assert begin.status_code == 200, begin.get_json()
    return begin.get_json()['publicKey']


def login_with(c, auth, options, credential_id_bytes, **kwargs):
    assertion = auth.get_assertion(
        options['rpId'], options['challenge'], 'http://localhost:5000',
        credential_id_bytes, user_handle=b'placeholder', **kwargs
    )
    return post(c, '/api/login/complete', assertion)


def stepup(c, auth):
    """Fresh assertion on an already-authenticated session — required before
    the server will attach another passkey."""
    begin = post(c, '/api/stepup/begin', {})
    if begin.status_code != 200:
        return begin
    options = begin.get_json()['publicKey']
    assertion = auth.get_assertion(
        options['rpId'], options['challenge'], 'http://localhost:5000',
        b64url_decode(options['allowCredentials'][0]['id']), user_handle=b'placeholder',
    )
    return post(c, '/api/stepup/complete', assertion)


# --- Registration ---
resp = register(client, authenticator, 'Ada Lovelace', 'ada@example.com')
body = resp.get_json()
check('register/complete returns verified=True', resp.status_code == 200 and body.get('verified') is True)
check('first registration returns 8 recovery codes', len(body.get('recoveryCodes', [])) == 8)

# --- Normal, email-first login ---
options = login_begin(client, 'ada@example.com')
credential_id_bytes = b64url_decode(options['allowCredentials'][0]['id'])
complete = login_with(client, authenticator, options, credential_id_bytes)
check('login/complete returns verified=True', complete.status_code == 200 and complete.get_json().get('verified') is True)

devices = client.get('/api/devices').get_json()['devices']
check('exactly one device registered', len(devices) == 1)

# --- Repeat login: only works if sign_count was actually persisted server-side ---
options2 = login_begin(client, 'ada@example.com')
complete2 = login_with(client, authenticator, options2, credential_id_bytes)
check('second login also succeeds (sign_count persisted correctly)',
      complete2.status_code == 200 and complete2.get_json().get('verified') is True)

# --- Conditional UI / discoverable login (no email typed) ---
options3 = login_begin(client, None)
check('conditional-login options have empty allowCredentials', options3['allowCredentials'] == [])
complete3 = login_with(client, authenticator, options3, credential_id_bytes)
check('conditional/discoverable login succeeds', complete3.status_code == 200 and complete3.get_json().get('verified') is True)

# --- Device management: add a 2nd device (authenticated session + step-up) ---
no_stepup = post(client, '/api/register/begin', {'name': 'Ada Lovelace', 'email': 'ada@example.com'})
check('adding a device on a stale session is refused without a fresh assertion',
      no_stepup.status_code == 401 and no_stepup.get_json().get('stepUpRequired') is True)

check('step-up from an unauthenticated client is refused',
      post(new_client(), '/api/stepup/begin', {}).status_code == 401)

check('step-up re-authentication succeeds', stepup(client, authenticator).status_code == 200)

add_resp = register(client, authenticator, 'Ada Lovelace', 'ada@example.com')
add_body = add_resp.get_json()
check('adding a 2nd device from an authenticated session succeeds',
      add_resp.status_code == 200 and add_body.get('verified') is True)
check('adding a 2nd device does not re-issue recovery codes', 'recoveryCodes' not in add_body)

devices2 = client.get('/api/devices').get_json()['devices']
check('now two devices registered', len(devices2) == 2)

first_cred_id = devices2[0]['credentialId']
rename_resp = post(client, f'/api/devices/{first_cred_id}/rename', {'name': 'My Laptop'})
check('rename device succeeds', rename_resp.status_code == 200)

devices3 = client.get('/api/devices').get_json()['devices']
check('renamed device shows the new name', any(d['deviceName'] == 'My Laptop' for d in devices3))

revoke_resp = delete(client, f'/api/devices/{first_cred_id}')
check('revoke device succeeds', revoke_resp.status_code == 200)

devices4 = client.get('/api/devices').get_json()['devices']
check('one device remains after revoke', len(devices4) == 1)

last_cred_id = devices4[0]['credentialId']
revoke_last_resp = delete(client, f'/api/devices/{last_cred_id}')
check('cannot revoke the last remaining device', revoke_last_resp.status_code == 400)

# --- #1: /api/register/begin must not authenticate anybody ---
attacker = new_client()
takeover_begin = post(attacker, '/api/register/begin', {'name': 'Mallory', 'email': 'ada@example.com'})
check('register/begin never issues recovery codes or a session',
      attacker.get('/api/session/whoami').status_code == 401)
check('pre-auth client cannot reach /api/devices', attacker.get('/api/devices').status_code == 401)
check('pre-auth client is bounced off /dashboard', attacker.get('/dashboard').status_code == 302)
check('pre-auth client is bounced off /devices', attacker.get('/devices').status_code == 302)

# A fresh, unknown email still gets a challenge but no identity until complete
probe = new_client()
probe_begin = post(probe, '/api/register/begin', {'name': 'Mallory', 'email': 'mallory@example.com'})
check('register/begin for a new email succeeds', probe_begin.status_code == 200)
check('register/begin does not authenticate the new email either',
      probe.get('/api/session/whoami').status_code == 401)

# --- #7: register/begin must not reveal whether the email is already taken ---
check('register/begin answers a taken email exactly like a free one',
      takeover_begin.status_code == probe_begin.status_code == 200)
check('register/begin bodies are structurally identical for taken and free emails',
      sorted(takeover_begin.get_json()['publicKey']) == sorted(probe_begin.get_json()['publicKey'])
      and takeover_begin.get_json()['publicKey']['excludeCredentials'] == []
      == probe_begin.get_json()['publicKey']['excludeCredentials'])

bad_email = post(new_client(), '/api/register/begin', {'name': 'Nope', 'email': 'not-an-email'})
check('a malformed email is rejected before it reaches the database', bad_email.status_code == 400)

# --- #2: an unauthenticated client cannot bolt its own passkey onto ada@example.com ---
mallory_auth = VirtualAuthenticator()
hijack = register(new_client(), mallory_auth, 'Mallory', 'ada@example.com')
check('unauthenticated passkey-add to an existing account is rejected', hijack.status_code == 400)
check('the taken-email failure is the same generic message as any other',
      hijack.get_json()['error'].startswith('Registration failed'))

# Emails are normalized, so case/whitespace cannot fork a second account
mixed_case = register(new_client(), VirtualAuthenticator(), 'Mallory', '  ADA@Example.com ')
check('a mixed-case duplicate email cannot create a second account', mixed_case.status_code == 400)
ada_devices = client.get('/api/devices').get_json()['devices']
check("victim's device list is unchanged after the hijack attempt", len(ada_devices) == 1)

# --- #3: CSRF token is required on state-changing routes ---
no_token = client.post('/api/devices/x/rename', json={'name': 'nope'})
check('rename without a CSRF token is rejected', no_token.status_code == 403)
bad_token = client.delete(f'/api/devices/{last_cred_id}', headers={'X-CSRF-Token': 'wrong'})
check('delete with a wrong CSRF token is rejected', bad_token.status_code == 403)

# --- Cross-user device deletion ---
bob_client = new_client()
bob_auth = VirtualAuthenticator()
bob_resp = register(bob_client, bob_auth, 'Bob', 'bob@example.com')
check('second user registers successfully', bob_resp.status_code == 200)
bob_devices = bob_client.get('/api/devices').get_json()['devices']
bob_cred_id = bob_devices[0]['credentialId']

cross_delete = delete(client, f'/api/devices/{bob_cred_id}')
check("cannot delete another user's device", cross_delete.status_code != 200)
cross_rename = post(client, f'/api/devices/{bob_cred_id}/rename', {'name': 'pwned'})
check("cannot rename another user's device", cross_rename.status_code == 404)
check("victim's device survives cross-user deletion",
      bob_client.get('/api/devices').get_json()['devices'][0]['credentialId'] == bob_cred_id)

# --- Tampered assertion signature ---
tamper_opts = login_begin(bob_client, 'bob@example.com')
tampered = bob_auth.get_assertion(
    tamper_opts['rpId'], tamper_opts['challenge'], 'http://localhost:5000',
    b64url_decode(tamper_opts['allowCredentials'][0]['id']), user_handle=b'placeholder')
sig = bytearray(b64url_decode(tampered['response']['signature']))
sig[-1] ^= 0xFF
tampered['response']['signature'] = b64url(bytes(sig))
tamper_resp = post(bob_client, '/api/login/complete', tampered)
check('a tampered signature is rejected', tamper_resp.status_code == 400)

# --- Challenge replay: the same assertion must not work twice ---
bob_client.get('/logout')
replay_opts = login_begin(bob_client, 'bob@example.com')
replay_cred_id = b64url_decode(replay_opts['allowCredentials'][0]['id'])
assertion = bob_auth.get_assertion(replay_opts['rpId'], replay_opts['challenge'],
                                   'http://localhost:5000', replay_cred_id, user_handle=b'placeholder')
first = post(bob_client, '/api/login/complete', assertion)
check('captured assertion authenticates once', first.status_code == 200)
bob_client.get('/logout')
replayed = post(bob_client, '/api/login/complete', assertion)
check('replaying the same assertion fails (challenge consumed)', replayed.status_code == 400)
check('replay did not create a session', bob_client.get('/api/session/whoami').status_code == 401)

# --- Registration challenge cannot be replayed either ---
replay_client = new_client()
reg_begin = post(replay_client, '/api/register/begin', {'name': 'Eve', 'email': 'eve@example.com'})
reg_opts = reg_begin.get_json()['publicKey']
eve_auth = VirtualAuthenticator()
reg_payload = eve_auth.create_credential(reg_opts['rp']['id'], reg_opts['challenge'], 'http://localhost:5000')
check('registration completes once', post(replay_client, '/api/register/complete', reg_payload).status_code == 200)
check('replaying the registration payload fails',
      post(replay_client, '/api/register/complete', reg_payload).status_code == 400)

# --- #6: /api/login/begin must not leak whether an account exists ---
known = post(new_client(), '/api/login/begin', {'email': 'ada@example.com'})
unknown = post(new_client(), '/api/login/begin', {'email': 'nosuchuser@example.com'})
check('login/begin answers 200 for an unknown email too', unknown.status_code == known.status_code == 200)
check('login/begin returns allowCredentials for an unknown email too',
      len(unknown.get_json()['publicKey']['allowCredentials']) >= 1)
check('login/begin bodies have the same shape for known and unknown emails',
      sorted(known.get_json()['publicKey']) == sorted(unknown.get_json()['publicKey']))

# The decoy set has to look like a plausible real account, and be stable:
# a count that changed between probes (or was always exactly 1) would be the
# tell that no such account exists.
decoy_counts = [
    len(post(new_client(), '/api/login/begin',
             {'email': f'ghost{i}@example.com'}).get_json()['publicKey']['allowCredentials'])
    for i in range(12)
]
check('decoy credential counts fall in the range a real account would',
      all(1 <= n <= 2 for n in decoy_counts))
check('decoy counts vary between unknown emails (never a constant "exactly 1" tell)',
      set(decoy_counts) == {1, 2})
repeat = post(new_client(), '/api/login/begin', {'email': 'ghost1@example.com'})
check('probing the same unknown email twice gives the same decoys',
      [c['id'] for c in repeat.get_json()['publicKey']['allowCredentials']]
      == [c['id'] for c in post(new_client(), '/api/login/begin',
                                {'email': 'ghost1@example.com'}).get_json()['publicKey']['allowCredentials']])

# --- Recovery codes: login without any authenticator at all ---
client.get('/logout')
recovery_resp = post(client, '/api/login/recovery', {'email': 'ada@example.com', 'code': body['recoveryCodes'][0]})
recovery_body = recovery_resp.get_json()
check('recovery code logs the user in', recovery_resp.status_code == 200 and recovery_body.get('verified') is True)
check('recovery issues a fresh set of 8 codes', len(recovery_body.get('recoveryCodes', [])) == 8)

reuse_resp = post(client, '/api/login/recovery', {'email': 'ada@example.com', 'code': body['recoveryCodes'][0]})
check('a used recovery code cannot be reused', reuse_resp.status_code == 400)

other_old_resp = post(client, '/api/login/recovery', {'email': 'ada@example.com', 'code': body['recoveryCodes'][3]})
check('the remaining old codes are invalidated after one is used', other_old_resp.status_code == 400)

new_code_resp = post(client, '/api/login/recovery',
                     {'email': 'ada@example.com', 'code': recovery_body['recoveryCodes'][0]})
check('a newly issued recovery code works', new_code_resp.status_code == 200)

unknown_account = post(new_client(), '/api/login/recovery',
                       {'email': 'nosuchuser@example.com', 'code': 'aaaa-bbbb-cccc'})
check('recovery error is identical for unknown accounts and bad codes',
      unknown_account.status_code == reuse_resp.status_code
      and unknown_account.get_json() == reuse_resp.get_json())

# --- Recovery codes are not stored as unsalted SHA-256 ---
from models import RecoveryCode  # noqa: E402

with app.app_context():
    stored = [r.code_hash for r in RecoveryCode.query.all()]
check('recovery codes are stored with a salted KDF, not a bare digest',
      stored and all(h.startswith('pbkdf2_sha256$') for h in stored))
check('every stored recovery code has its own salt',
      len({h.split('$')[2] for h in stored}) == len(stored))

# --- Cookie hardening ---
check('session cookie is HttpOnly', app.config['SESSION_COOKIE_HTTPONLY'] is True)
check('session cookie is SameSite', app.config['SESSION_COOKIE_SAMESITE'] in ('Lax', 'Strict'))
check('session lifetime is bounded', app.config['PERMANENT_SESSION_LIFETIME'].total_seconds() > 0)

import database  # noqa: E402
from models import User, db  # noqa: E402

# --- #1: user verification is enforced by the SERVER, not just requested ---
# "userVerification: required" in the options is advice to the client. These
# two checks fail unless verify_*_response gets require_user_verification=True.
uv_client = new_client()
uv_auth = VirtualAuthenticator()
uv_opts = post(uv_client, '/api/register/begin',
               {'name': 'No UV', 'email': 'nouv@example.com'}).get_json()['publicKey']
check('register/begin asks the client for user verification',
      uv_opts['authenticatorSelection']['userVerification'] == 'required')
uv_reg = uv_auth.create_credential(uv_opts['rp']['id'], uv_opts['challenge'],
                                   'http://localhost:5000', user_verified=False)
check('a registration with the UV flag clear is rejected',
      post(uv_client, '/api/register/complete', uv_reg).status_code == 400)
with app.app_context():
    check('the UV-less registration created no account',
          User.query.filter_by(email='nouv@example.com').first() is None)

uv_login = new_client()
uv_login_opts = login_begin(uv_login, 'bob@example.com')
bob_cred_bytes = b64url_decode(uv_login_opts['allowCredentials'][0]['id'])
check('a login assertion with the UV flag clear is rejected',
      login_with(uv_login, bob_auth, uv_login_opts, bob_cred_bytes, user_verified=False).status_code == 400)
check('the rejected UV-less assertion created no session',
      uv_login.get('/api/session/whoami').status_code == 401)

uv_control = new_client()
check('control: the same authenticator with UV set still logs in',
      login_with(uv_control, bob_auth, login_begin(uv_control, 'bob@example.com'),
                 bob_cred_bytes).status_code == 200)

# --- Cloned authenticator: a sign counter that goes backwards ---
sc_client = new_client()
check('an assertion replaying an old sign counter is rejected',
      login_with(sc_client, bob_auth, login_begin(sc_client, 'bob@example.com'),
                 bob_cred_bytes, sign_count=1).status_code == 400)

# --- Assertions signed for the wrong rpId / origin ---
rp_client = new_client()
rp_opts = login_begin(rp_client, 'bob@example.com')
wrong_rp = bob_auth.get_assertion('evil.example', rp_opts['challenge'], 'http://localhost:5000',
                                  bob_cred_bytes, user_handle=b'placeholder')
check('an assertion signed for a different rpId is rejected',
      post(rp_client, '/api/login/complete', wrong_rp).status_code == 400)

origin_client = new_client()
origin_opts = login_begin(origin_client, 'bob@example.com')
wrong_origin = bob_auth.get_assertion(origin_opts['rpId'], origin_opts['challenge'],
                                      'https://evil.example', bob_cred_bytes, user_handle=b'placeholder')
check('an assertion from a different origin is rejected',
      post(origin_client, '/api/login/complete', wrong_origin).status_code == 400)

# --- Challenges expire ---
exp_client = new_client()
exp_opts = login_begin(exp_client, 'bob@example.com')
with exp_client.session_transaction() as sess:
    sess['login_challenge'] = {**sess['login_challenge'], 'expires_at': time.time() - 1}
check('an expired login challenge is rejected',
      login_with(exp_client, bob_auth, exp_opts, bob_cred_bytes).status_code == 400)

exp_reg_client = new_client()
exp_reg_opts = post(exp_reg_client, '/api/register/begin',
                    {'name': 'Stale', 'email': 'stale@example.com'}).get_json()['publicKey']
with exp_reg_client.session_transaction() as sess:
    sess['pending_registration'] = {**sess['pending_registration'], 'expires_at': time.time() - 1}
stale_reg = VirtualAuthenticator().create_credential(
    exp_reg_opts['rp']['id'], exp_reg_opts['challenge'], 'http://localhost:5000')
check('an expired registration challenge is rejected',
      post(exp_reg_client, '/api/register/complete', stale_reg).status_code == 400)

# --- Cross-ceremony challenge reuse ---
cross_client = new_client()
cross_opts = post(cross_client, '/api/register/begin',
                  {'name': 'Cross', 'email': 'cross@example.com'}).get_json()['publicKey']
cross_assertion = bob_auth.get_assertion(cross_opts['rp']['id'], cross_opts['challenge'],
                                         'http://localhost:5000', bob_cred_bytes, user_handle=b'placeholder')
check('a registration challenge cannot be used to complete a login',
      post(cross_client, '/api/login/complete', cross_assertion).status_code == 400)
check('the cross-ceremony attempt created no session',
      cross_client.get('/api/session/whoami').status_code == 401)

cross_client2 = new_client()
cross_login_opts = login_begin(cross_client2, 'bob@example.com')
cross_reg = VirtualAuthenticator().create_credential(
    'localhost', cross_login_opts['challenge'], 'http://localhost:5000')
check('a login challenge cannot be used to complete a registration',
      post(cross_client2, '/api/register/complete', cross_reg).status_code == 400)

# --- Step-up must be an assertion from THIS account ---
foreign_opts = post(client, '/api/stepup/begin', {}).get_json()['publicKey']
foreign_assertion = bob_auth.get_assertion(foreign_opts['rpId'], foreign_opts['challenge'],
                                           'http://localhost:5000', bob_cred_bytes, user_handle=b'placeholder')
check("step-up with another account's passkey is rejected",
      post(client, '/api/stepup/complete', foreign_assertion).status_code == 400)
check('a rejected step-up does not unlock add-device',
      post(client, '/api/register/begin',
           {'name': 'Ada Lovelace', 'email': 'ada@example.com'}).status_code == 401)

# --- #3: sessions can be killed server-side, not just in one browser ---
carol = new_client()
carol_auth = VirtualAuthenticator()
check('third user registers successfully',
      register(carol, carol_auth, 'Carol', 'carol@example.com').status_code == 200)

stolen = new_client()
stolen.set_cookie('session', carol.get_cookie('session').value)
check('a copied session cookie works while the session is live',
      stolen.get('/api/session/whoami').status_code == 200)
carol.get('/logout')
check('logout kills the copied cookie too, not just the browser that logged out',
      stolen.get('/api/session/whoami').status_code == 401)

carol_opts = login_begin(carol, 'carol@example.com')
carol_cred = b64url_decode(carol_opts['allowCredentials'][0]['id'])
check('carol logs back in', login_with(carol, carol_auth, carol_opts, carol_cred).status_code == 200)
check('carol re-authenticates for a step-up', stepup(carol, carol_auth).status_code == 200)
check('carol adds a second device',
      register(carol, carol_auth, 'Carol', 'carol@example.com').status_code == 200)

stolen2 = new_client()
stolen2.set_cookie('session', carol.get_cookie('session').value)
check('the newly issued session cookie is live', stolen2.get('/api/session/whoami').status_code == 200)
carol_devices = carol.get('/api/devices').get_json()['devices']
check('carol revokes her first device',
      delete(carol, f"/api/devices/{carol_devices[0]['credentialId']}").status_code == 200)
check('revoking a device kills every session issued before the revoke',
      stolen2.get('/api/session/whoami').status_code == 401)
check('the session that did the revoking stays signed in',
      carol.get('/api/session/whoami').status_code == 200)

# --- #6: security headers ---
page = client.get('/dashboard')
csp = page.headers.get('Content-Security-Policy', '')
check('X-Frame-Options is DENY', page.headers.get('X-Frame-Options') == 'DENY')
check('X-Content-Type-Options is nosniff', page.headers.get('X-Content-Type-Options') == 'nosniff')
check('authenticated pages are not cached', page.headers.get('Cache-Control') == 'no-store')
check('API responses are not cached', client.get('/api/devices').headers.get('Cache-Control') == 'no-store')
check('CSP forbids framing and plugins',
      "frame-ancestors 'none'" in csp and "object-src 'none'" in csp)
check("CSP script-src has no 'unsafe-inline'", "'unsafe-inline'" not in csp.split('style-src')[0])
nonce = re.search(r'<script nonce="([^"]+)"', page.get_data(as_text=True))
check('inline scripts carry a nonce the CSP header allows',
      nonce is not None and f"'nonce-{nonce.group(1)}'" in csp)
check('no inline <script> is left un-nonced', '<script>' not in page.get_data(as_text=True))
check('the nonce is fresh on every response',
      re.search(r'<script nonce="([^"]+)"',
                client.get('/dashboard').get_data(as_text=True)).group(1) != nonce.group(1))
check('HSTS is not sent on a plain-http origin',
      page.headers.get('Strict-Transport-Security') is None)
devices_page = client.get('/devices')
devices_nonce = re.search(r'<script nonce="([^"]+)"', devices_page.get_data(as_text=True))
check('the devices page renders with a nonce its own CSP header allows',
      devices_page.status_code == 200 and devices_nonce is not None
      and f"'nonce-{devices_nonce.group(1)}'" in devices_page.headers.get('Content-Security-Policy', ''))
check('an oversized request body is refused',
      post(new_client(), '/api/register/begin',
           {'name': 'x' * 70000, 'email': 'big@example.com'}).status_code == 413)

# --- #5/#6: an https ORIGIN really does produce Secure cookies and HSTS ---
_https_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
_https_db.close()
_probe = (
    'import sys; sys.path.insert(0, %r)\n' % REPO_ROOT +
    'from app import app\n'
    'r = app.test_client().get("/login")\n'
    'print("CONFIG", app.config["SESSION_COOKIE_SECURE"])\n'
    'print("COOKIE", "Secure" in r.headers.get("Set-Cookie", ""))\n'
    'print("HSTS", bool(r.headers.get("Strict-Transport-Security")))\n'
)
_https_env = dict(os.environ, ORIGIN='https://securepass.example', RP_ID='securepass.example',
                  SECRET_KEY='test-secret-key', DATABASE_PATH=_https_db.name)
_https_out = subprocess.run([sys.executable, '-c', _probe], env=_https_env,
                            capture_output=True, text=True).stdout
check('an https ORIGIN sets SESSION_COOKIE_SECURE', 'CONFIG True' in _https_out)
check('the session cookie is actually sent with Secure', 'COOKIE True' in _https_out)
check('HSTS is sent on an https origin', 'HSTS True' in _https_out)

_missing_secret = dict(os.environ)
_missing_secret.pop('SECRET_KEY', None)
_missing_secret.pop('FLASK_DEBUG', None)
_missing_secret['DATABASE_PATH'] = _https_db.name
check('the app refuses to start without SECRET_KEY outside debug',
      subprocess.run([sys.executable, '-c', 'import app'], env=_missing_secret,
                     capture_output=True, text=True).returncode != 0)

# --- #4: recovery lookup does a fixed amount of work ---
_verify_calls = []
_orig_verify = database._verify_code


def _counting_verify(code, stored):
    _verify_calls.append(stored)
    return _orig_verify(code, stored)


database._verify_code = _counting_verify
with app.app_context():
    database.consume_recovery_code('ada@example.com', 'aaaa-bbbb-cccc')
    known_cost = len(_verify_calls)
    _verify_calls.clear()
    database.consume_recovery_code('nobody@example.com', 'aaaa-bbbb-cccc')
    unknown_cost = len(_verify_calls)
database._verify_code = _orig_verify
check('a wrong code costs one KDF verification, not one per unused code (8 here)',
      known_cost == 1)
check('an unknown email costs exactly the same work', unknown_cost == known_cost)

# --- #4: per-account lockout, independent of the per-IP rate limit ---
valid_code = new_code_resp.get_json()['recoveryCodes'][0]
with app.app_context():
    for _ in range(database._RECOVERY_MAX_FAILURES):
        database.consume_recovery_code('ada@example.com', 'aaaa-bbbb-cccc')
    locked_attempt = database.consume_recovery_code('ada@example.com', valid_code)
    ada_row = User.query.filter_by(email='ada@example.com').first()
    lock_until, failures_seen = ada_row.recovery_locked_until, ada_row.recovery_failures
check('repeated wrong recovery codes lock the account', locked_attempt is None)
check('the lockout is recorded with an expiry',
      failures_seen >= database._RECOVERY_MAX_FAILURES
      and lock_until is not None and lock_until > datetime.utcnow())
with app.app_context():
    ada_row = User.query.filter_by(email='ada@example.com').first()
    ada_row.recovery_locked_until = None
    ada_row.recovery_failures = 0
    db.session.commit()
    after_lockout = database.consume_recovery_code('ada@example.com', valid_code)
check('the code was still valid, so it was the lockout that refused it', after_lockout is not None)

with app.app_context():
    all_codes = RecoveryCode.query.all()
check('every stored recovery code carries a lookup index',
      all_codes and all(c.code_index for c in all_codes))

# --- Rate limiting on login/begin ---
client.get('/logout')
token = csrf(client)
limit_hit = any(
    client.post('/api/login/begin', json={'email': 'nobody@example.com'},
                headers={'X-CSRF-Token': token}).status_code == 429
    for _ in range(20)
)
check('login/begin gets rate limited under repeated hits', limit_hit)

print()
for _leftover in (_tmp_db.name, _https_db.name):
    try:
        os.unlink(_leftover)
    except OSError:
        pass  # Windows keeps the sqlite file locked while the pooled connection is open; harmless
if failures:
    print(f'{len(failures)} check(s) FAILED:')
    for f in failures:
        print(' -', f)
    sys.exit(1)
print(f'All {total_checks} checks passed.')
