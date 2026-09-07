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
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.dirname(__file__))

_tmp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
_tmp_db.close()
os.environ['DATABASE_PATH'] = _tmp_db.name
os.environ.setdefault('SECRET_KEY', 'test-secret-key')

from app import app  # noqa: E402  (must import after env vars are set)
from virtual_authenticator import VirtualAuthenticator, b64url, b64url_decode  # noqa: E402

client = app.test_client()
authenticator = VirtualAuthenticator()
failures = []
total_checks = 0


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


def login_with(c, auth, options, credential_id_bytes):
    assertion = auth.get_assertion(
        options['rpId'], options['challenge'], 'http://localhost:5000',
        credential_id_bytes, user_handle=b'placeholder',
    )
    return post(c, '/api/login/complete', assertion)


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

# --- Device management: add a 2nd device (requires the authenticated session) ---
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
attacker = app.test_client()
takeover_begin = post(attacker, '/api/register/begin', {'name': 'Mallory', 'email': 'ada@example.com'})
check('register/begin on an existing email is rejected', takeover_begin.status_code == 400)
check('register/begin never issues recovery codes or a session',
      attacker.get('/api/session/whoami').status_code == 401)
check('pre-auth client cannot reach /api/devices', attacker.get('/api/devices').status_code == 401)
check('pre-auth client is bounced off /dashboard', attacker.get('/dashboard').status_code == 302)
check('pre-auth client is bounced off /devices', attacker.get('/devices').status_code == 302)

# A fresh, unknown email still gets a challenge but no identity until complete
probe = app.test_client()
probe_begin = post(probe, '/api/register/begin', {'name': 'Mallory', 'email': 'mallory@example.com'})
check('register/begin for a new email succeeds', probe_begin.status_code == 200)
check('register/begin does not authenticate the new email either',
      probe.get('/api/session/whoami').status_code == 401)

# --- #2: an unauthenticated client cannot bolt its own passkey onto ada@example.com ---
mallory_auth = VirtualAuthenticator()
hijack = register(app.test_client(), mallory_auth, 'Mallory', 'ada@example.com')
check('unauthenticated passkey-add to an existing account is rejected', hijack.status_code == 400)
ada_devices = client.get('/api/devices').get_json()['devices']
check("victim's device list is unchanged after the hijack attempt", len(ada_devices) == 1)

# --- #3: CSRF token is required on state-changing routes ---
no_token = client.post('/api/devices/x/rename', json={'name': 'nope'})
check('rename without a CSRF token is rejected', no_token.status_code == 403)
bad_token = client.delete(f'/api/devices/{last_cred_id}', headers={'X-CSRF-Token': 'wrong'})
check('delete with a wrong CSRF token is rejected', bad_token.status_code == 403)

# --- Cross-user device deletion ---
bob_client = app.test_client()
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
replay_client = app.test_client()
reg_begin = post(replay_client, '/api/register/begin', {'name': 'Eve', 'email': 'eve@example.com'})
reg_opts = reg_begin.get_json()['publicKey']
eve_auth = VirtualAuthenticator()
reg_payload = eve_auth.create_credential(reg_opts['rp']['id'], reg_opts['challenge'], 'http://localhost:5000')
check('registration completes once', post(replay_client, '/api/register/complete', reg_payload).status_code == 200)
check('replaying the registration payload fails',
      post(replay_client, '/api/register/complete', reg_payload).status_code == 400)

# --- #6: /api/login/begin must not leak whether an account exists ---
known = post(app.test_client(), '/api/login/begin', {'email': 'ada@example.com'})
unknown = post(app.test_client(), '/api/login/begin', {'email': 'nosuchuser@example.com'})
check('login/begin answers 200 for an unknown email too', unknown.status_code == known.status_code == 200)
check('login/begin returns allowCredentials for an unknown email too',
      len(unknown.get_json()['publicKey']['allowCredentials']) == 1)

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

unknown_account = post(app.test_client(), '/api/login/recovery',
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
try:
    os.unlink(_tmp_db.name)
except OSError:
    pass  # Windows keeps the sqlite file locked while the pooled connection is open; harmless
if failures:
    print(f'{len(failures)} check(s) FAILED:')
    for f in failures:
        print(' -', f)
    sys.exit(1)
print(f'All {total_checks} checks passed.')
