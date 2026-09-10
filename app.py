import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import timedelta

from flask import Flask, g, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
    PublicKeyCredentialDescriptor
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from database import (
    init_db,
    create_user_with_credential,
    normalize_email,
    bump_session_epoch,
    get_user_by_email,
    get_user_by_id,
    add_credential,
    get_user_credentials,
    get_credential_by_id,
    update_sign_count,
    rename_credential,
    delete_credential,
    generate_recovery_codes,
    consume_recovery_code,
)

# Helper: decode base64url (no padding) to bytes
def base64url_to_bytes(val: str) -> bytes:
    if not val:
        return b''
    # convert base64url to standard base64
    s = val.replace('-', '+').replace('_', '/')
    # add padding
    padding = '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + padding)


def bytes_to_base64url(b: bytes) -> str:
    if not b:
        return ''
    s = base64.b64encode(b).decode()
    # convert to base64url and strip padding
    return s.replace('+', '-').replace('/', '_').rstrip('=')


def guess_device_name(user_agent: str, authenticator_attachment) -> str:
    """Best-effort, dependency-free label for a newly registered credential.
    The WebAuthn API doesn't hand us a device name, so this reads the
    User-Agent the browser already sent us."""
    ua = (user_agent or '').lower()

    if 'iphone' in ua:
        os_name = 'iPhone'
    elif 'ipad' in ua:
        os_name = 'iPad'
    elif 'android' in ua:
        os_name = 'Android'
    elif 'mac os x' in ua or 'macintosh' in ua:
        os_name = 'Mac'
    elif 'windows' in ua:
        os_name = 'Windows'
    elif 'linux' in ua:
        os_name = 'Linux'
    else:
        os_name = 'Unknown device'

    if 'edg/' in ua:
        browser = 'Edge'
    elif 'chrome/' in ua:
        browser = 'Chrome'
    elif 'firefox/' in ua:
        browser = 'Firefox'
    elif 'safari/' in ua:
        browser = 'Safari'
    else:
        browser = ''

    label = f'{os_name} · {browser}' if browser else os_name
    if authenticator_attachment == 'cross-platform':
        label += ' (via phone/security key)'
    return label


app = Flask(__name__)

DEBUG = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')

app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    if not DEBUG:
        raise RuntimeError(
            'SECRET_KEY is not set. Refusing to start: a per-process random key silently '
            'invalidates every session on restart, and each worker of a multi-process '
            'deployment would sign cookies with a different key. Set SECRET_KEY (or set '
            'FLASK_DEBUG=1 for local development).')
    app.secret_key = secrets.token_hex(32)
    print('WARNING: SECRET_KEY is not set — using a random key for this process only. '
          'Every restart will invalidate all existing sessions and all outstanding '
          'recovery codes. Set the SECRET_KEY environment variable for a real deployment.')

# Behind a reverse proxy, get_remote_address() otherwise sees the proxy's IP and
# rate-limits every client as one. Opt-in and explicit about how many proxies to
# trust: enabling this without a proxy in front would let anyone spoof
# X-Forwarded-For and get a fresh rate-limit bucket per request.
TRUSTED_PROXY_HOPS = int(os.environ.get('TRUSTED_PROXY_HOPS', '0'))
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS,
                            x_proto=TRUSTED_PROXY_HOPS, x_host=TRUSTED_PROXY_HOPS)

# WebAuthn configuration — override via env vars for anything beyond local dev.
# WebAuthn requires HTTPS (or "localhost") in real deployments; RP_ID must be
# the exact domain, and ORIGIN the exact scheme+host+port the browser sees.
RP_ID = os.environ.get('RP_ID', 'localhost')
RP_NAME = os.environ.get('RP_NAME', 'SecurePass')
ORIGIN = os.environ.get('ORIGIN', 'http://localhost:5000')

# Cookie hardening. Secure follows the deployment origin so local http dev
# still works, but any https deployment gets Secure cookies automatically.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get(
        'SESSION_COOKIE_SECURE', '1' if ORIGIN.startswith('https://') else '0'
    ).lower() in ('1', 'true', 'yes'),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    # Every endpoint here takes a small JSON body; the largest is a WebAuthn
    # attestation at a couple of KB. Anything bigger is rejected before it is
    # buffered or parsed.
    MAX_CONTENT_LENGTH=65536,
)

# A WebAuthn ceremony that isn't finished within this window has to restart.
CHALLENGE_TTL_SECONDS = 300

# How long a step-up re-authentication stays good for. Adding a passkey is an
# account-takeover-grade action, so a borrowed/left-open session must not be
# enough on its own.
STEPUP_TTL_SECONDS = 120

# Deliberately loose: real-world addresses are far weirder than any regex, so
# this only rejects the obviously malformed and leaves proof of ownership to
# the passkey itself.
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$')

# Deliberately identical for "email already taken", "verification failed" and
# any other registration problem — the response must not confirm whether an
# account exists.
REGISTRATION_FAILED = 'Registration failed. If you already have an account, log in instead.'
AUTHENTICATION_FAILED = 'Authentication failed'
RECOVERY_FAILED = 'Invalid or already-used recovery code'

# Initialize database
init_db(app)

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])


def _new_csrf_token():
    session.permanent = True
    session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


@app.before_request
def reject_oversized_bodies():
    """MAX_CONTENT_LENGTH alone only fires when the body is actually read,
    which every route here does inside its own try/except — so the caller
    would get a misleading generic failure. Refuse up front instead. (The
    config value still backstops a lying or absent Content-Length.)"""
    if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': 'Request too large'}), 413
    return None


@app.before_request
def csrf_protect():
    """Double-submit CSRF check: the token lives in the (HttpOnly, SameSite)
    session cookie and must be echoed back in a header, which cross-site
    JavaScript cannot read or set."""
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None
    expected = session.get('csrf_token')
    provided = request.headers.get('X-CSRF-Token', '')
    if not expected or not hmac.compare_digest(expected, provided):
        return jsonify({'error': 'Invalid or missing CSRF token'}), 403
    return None


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': session.get('csrf_token') or _new_csrf_token(),
            'csp_nonce': csp_nonce()}


def csp_nonce():
    """Per-response nonce for the handful of inline <script> blocks in the
    templates, so script-src can stay free of 'unsafe-inline'."""
    if not hasattr(g, '_csp_nonce'):
        g._csp_nonce = secrets.token_urlsafe(16)
    return g._csp_nonce


@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = '; '.join([
        "default-src 'self'",
        f"script-src 'self' 'nonce-{csp_nonce()}'",
        # Only for the inline style="" attributes left in the templates; no
        # inline <style> or script is allowed by this.
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "object-src 'none'",
        "frame-ancestors 'none'",
    ])
    # Everything this app serves outside /static is either an API response or a
    # page rendered for one specific signed-in user — none of it may be cached
    # by a browser or an intermediary.
    if not request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-store'
    if ORIGIN.startswith('https://'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


def establish_session(user_id, user_email, session_epoch):
    """Called ONLY after a completed, verified ceremony. Clears everything
    first so a pre-auth session can never be upgraded in place (session
    fixation), and mints a fresh CSRF token."""
    session.clear()
    session.permanent = True
    session['user_id'] = user_id
    session['user_email'] = user_email
    # Pinning the epoch is what makes a session revocable server-side: bumping
    # the stored value (logout, device revoke) orphans every cookie issued
    # before it, whatever their expiry says.
    session['session_epoch'] = session_epoch
    session['authenticated'] = True
    _new_csrf_token()


def _decoy_prf(email: str, label: str) -> bytes:
    key = app.secret_key.encode() if isinstance(app.secret_key, str) else app.secret_key
    return hmac.new(key, f'{label}:{email}'.encode(), hashlib.sha256).digest()


def decoy_credentials(email: str):
    """Stable, unguessable credential ids for an email we have no passkey for,
    so /api/login/begin answers unknown and known accounts identically. The
    count is derived from the email too: always returning exactly one made the
    decoy set itself the tell, since real accounts here routinely have two
    (this device plus a phone)."""
    count = 1 + _decoy_prf(email, 'decoy-count')[0] % 2
    return [PublicKeyCredentialDescriptor(id=_decoy_prf(email, f'decoy:{i}'))
            for i in range(count)]


def current_user():
    # 'authenticated' is set exclusively by establish_session(), i.e. only
    # after a verified WebAuthn assertion/attestation or a recovery code.
    if not session.get('authenticated'):
        return None
    user_id = session.get('user_id')
    user_email = session.get('user_email')
    if not user_id or not user_email:
        return None
    user = get_user_by_email(user_email)
    if not user or user['id'] != user_id:
        return None
    # Server-side revocation check: a cookie minted before the last logout or
    # device revoke carries a stale epoch and is dead on arrival.
    if session.get('session_epoch') != user['session_epoch']:
        return None
    return user


@app.route('/')
def index():
    if current_user():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/devices')
def devices_page():
    user = current_user()
    if not user:
        return redirect(url_for('index'))
    return render_template('devices.html', user=user)

@app.route('/dashboard')
def dashboard():
    user = current_user()
    if not user:
        print("Dashboard access denied: invalid or missing session")
        session.clear()
        return redirect(url_for('index'))

    try:
        credentials = get_user_credentials(user['id'])
        credential_count = len(credentials) if credentials else 0
    except Exception as e:
        print(f"Error getting user credentials: {e}")
        credential_count = 0

    return render_template('dashboard.html', user=user, credential_count=credential_count)

@app.route('/logout')
def logout():
    user = current_user()
    if user:
        # Dropping the cookie only asks the browser to forget it. Bumping the
        # epoch is what actually kills the session everywhere it was copied to.
        bump_session_epoch(user['id'])
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/session/whoami')
def session_whoami():
    user = current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({'name': user['name'], 'email': user['email']})

@app.route('/api/register/begin', methods=['POST'])
@limiter.limit('10 per minute')
def register_begin():
    try:
        data = request.get_json(silent=True) or {}

        # Two distinct flows, never mixed:
        #   * authenticated session -> add another device to THAT account,
        #     identity taken from the session, never from the request body;
        #   * no session -> brand new signup, where the email is only a claim
        #     until /complete (matching an email is not proof of owning the
        #     account).
        user = current_user()
        if user:
            mode = 'add_device'
            # A live session is not enough to bolt a permanent new passkey onto
            # the account: an unlocked laptop or a stolen cookie would be a
            # silent, self-service account takeover. Demand a fresh assertion.
            if time.time() - session.get('stepup_at', 0) > STEPUP_TTL_SECONDS:
                return jsonify({'error': 'Re-authentication required', 'stepUpRequired': True}), 401
            user_id, name, email = user['id'], user['name'], user['email']
            exclude_credentials = [
                PublicKeyCredentialDescriptor(id=base64.b64decode(cred['credential_id']))
                for cred in get_user_credentials(user_id)
            ]
        else:
            mode = 'signup'
            name = (data.get('name') or '').strip()
            email = normalize_email(data.get('email'))
            if not name or not email:
                return jsonify({'error': 'Name and email are required'}), 400
            if len(name) > 255 or len(email) > 254 or not EMAIL_RE.match(email):
                return jsonify({'error': 'Please enter a valid name and email address'}), 400
            # Deliberately NOT checking whether the email is taken: answering
            # differently here would turn this endpoint into a "does this
            # person have an account?" oracle for anyone who can POST. A
            # collision is caught atomically at /complete, where the answer is
            # the same generic failure as any other registration problem.
            user_id = secrets.token_hex(32)
            exclude_credentials = []

        # "Add another device" always means a device OTHER than the one
        # already sitting here — e.g. scan a QR to link a phone. Without
        # this hint, the browser defaults to this machine's own platform
        # authenticator, which just collides with excludeCredentials above
        # if this device is already registered.
        authenticator_selection_kwargs = {
            'resident_key': ResidentKeyRequirement.PREFERRED,
            'user_verification': UserVerificationRequirement.REQUIRED,
        }
        if data.get('crossPlatform'):
            authenticator_selection_kwargs['authenticator_attachment'] = AuthenticatorAttachment.CROSS_PLATFORM

        # Generate registration options
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=str(user_id),
            user_name=email,
            user_display_name=name,
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(**authenticator_selection_kwargs),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ]
        )

        # Ceremony state lives under its own key and carries no authority:
        # nothing here makes current_user() return anybody.
        session['pending_registration'] = {
            'mode': mode,
            'user_id': user_id,
            'name': name,
            'email': email,
            'challenge': bytes_to_base64url(options.challenge),
            'expires_at': time.time() + CHALLENGE_TTL_SECONDS,
        }

        return jsonify({
            'publicKey': {
                'challenge': bytes_to_base64url(options.challenge),
                'rp': {'id': options.rp.id, 'name': options.rp.name},
                'user': {
                    'id': bytes_to_base64url(options.user.id),
                    'name': options.user.name,
                    'displayName': options.user.display_name
                },
                'pubKeyCredParams': [{'alg': alg.alg, 'type': 'public-key'} for alg in options.pub_key_cred_params],
                'timeout': options.timeout,
                'excludeCredentials': [
                    {
                        'id': bytes_to_base64url(cred.id),
                        'type': cred.type,
                        **({'transports': list(cred.transports)} if cred.transports else {})
                    } for cred in options.exclude_credentials
                ] if options.exclude_credentials else [],
                'authenticatorSelection': {
                    'authenticatorAttachment': options.authenticator_selection.authenticator_attachment,
                    'residentKey': options.authenticator_selection.resident_key,
                    'requireResidentKey': options.authenticator_selection.require_resident_key,
                    'userVerification': options.authenticator_selection.user_verification
                },
                'attestation': options.attestation
            }
        })
    except Exception:
        app.logger.exception('Registration begin error')
        return jsonify({'error': REGISTRATION_FAILED}), 400

@app.route('/api/register/complete', methods=['POST'])
@limiter.limit('20 per minute')
def register_complete():
    try:
        data = request.get_json(silent=True) or {}
        # Build RegistrationCredential manually from browser JSON
        # data contains base64url-encoded strings for rawId and response fields
        raw_id_bytes = base64url_to_bytes(data.get('rawId'))
        attestation_obj = base64url_to_bytes(data.get('response', {}).get('attestationObject'))
        client_data = base64url_to_bytes(data.get('response', {}).get('clientDataJSON'))

        attestation_response = AuthenticatorAttestationResponse(
            client_data_json=client_data,
            attestation_object=attestation_obj,
            transports=None
        )

        credential = RegistrationCredential(
            id=data.get('id'),
            raw_id=raw_id_bytes,
            response=attestation_response,
            authenticator_attachment=data.get('authenticatorAttachment'),
            type=data.get('type')
        )

        # Pop before anything else: a challenge is single-use, so even a
        # failed attempt burns it and cannot be replayed.
        pending = session.pop('pending_registration', None)
        if not pending or pending.get('expires_at', 0) < time.time():
            return jsonify({'error': 'Registration session expired — please start again'}), 400

        challenge = base64url_to_bytes(pending['challenge'])
        # Keep user_id as the original string (don't convert to bytes) so DB keys stay consistent
        user_id = pending['user_id']
        user_name = pending['name']
        user_email = pending['email']
        is_new_user = pending['mode'] == 'signup'

        if not is_new_user:
            # Adding a device requires the session to still belong to exactly
            # the account the ceremony was started for, and the step-up
            # re-authentication to still be fresh.
            session_user = current_user()
            if not session_user or session_user['id'] != user_id:
                return jsonify({'error': 'Not authenticated'}), 401
            if time.time() - session.get('stepup_at', 0) > STEPUP_TTL_SECONDS:
                return jsonify({'error': 'Re-authentication required', 'stepUpRequired': True}), 401

        # Verify registration response
        # If verification fails, it will raise an exception.
        # require_user_verification is what actually enforces the biometric /
        # PIN: the "userVerification: required" we send in the options is a
        # request to the client, and a client is free to ignore it.
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True
        )

        # Store credential in database
        # Ensure binary fields are stored as base64 strings in the database
        client_data_b64 = (credential.response.client_data_json
                           if isinstance(credential.response.client_data_json, str)
                           else base64.b64encode(credential.response.client_data_json).decode())
        attestation_b64 = (credential.response.attestation_object
                           if isinstance(credential.response.attestation_object, str)
                           else base64.b64encode(credential.response.attestation_object).decode())

        device_name = guess_device_name(request.headers.get('User-Agent', ''), credential.authenticator_attachment)

        new_credential = {
            'credential_id': base64.b64encode(verification.credential_id).decode(),
            'public_key': base64.b64encode(verification.credential_public_key).decode(),
            'sign_count': verification.sign_count,
            'client_data_json': client_data_b64,
            'attestation_object': attestation_b64,
            'device_name': device_name,
        }

        response = {'verified': True}
        if is_new_user:
            # One transaction: user row, first passkey and recovery codes land
            # together or not at all. It also settles the taken-email race
            # atomically — no separate check-then-insert window — and returns
            # the same generic failure either way.
            recovery_codes = create_user_with_credential(user_id, user_name, user_email, new_credential)
            if recovery_codes is None:
                return jsonify({'error': REGISTRATION_FAILED}), 400
            created = get_user_by_id(user_id)
            # Verified ceremony — only now does this session get an identity.
            establish_session(user_id, created['email'], created['session_epoch'])
            # Shown to the user exactly once — WebAuthn has no password reset,
            # so a lost/broken authenticator needs a backup way in.
            response['recoveryCodes'] = recovery_codes
        else:
            add_credential(user_id, **new_credential)
            # Add-device already runs in an authenticated session; re-establishing
            # it would needlessly rotate the CSRF token of the open page. The
            # step-up is single-use, so a second device needs a second assertion.
            session.pop('stepup_at', None)

        app.logger.info('Registration completed (new_user=%s)', is_new_user)
        return jsonify(response)

    except Exception:
        app.logger.exception('Registration verification failed')
        return jsonify({'error': REGISTRATION_FAILED}), 400

@app.route('/api/login/begin', methods=['POST'])
@limiter.limit('15 per minute')
def login_begin():
    try:
        data = request.get_json(silent=True) or {}
        email = normalize_email(data.get('email'))

        allow_credentials = []
        if email:
            user = get_user_by_email(email)
            credentials = get_user_credentials(user['id']) if user else []
            if credentials:
                allow_credentials = [
                    PublicKeyCredentialDescriptor(id=base64.b64decode(cred['credential_id']))
                    for cred in credentials
                ]
            else:
                # Unknown email (or an account with no passkey yet) must look
                # exactly like a known one, otherwise this endpoint is a user
                # -enumeration oracle. The decoys are derived from the email so
                # probing the same address twice gives the same answer.
                allow_credentials = decoy_credentials(email)
        # else: no email yet — this is the passive "conditional UI" autofill
        # request. Leaving allowCredentials empty lets the browser offer any
        # discoverable passkey registered for this RP, no email typed first.

        # Generate authentication options
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.REQUIRED
        )

        # Store challenge in session (base64url), under a login-only key so a
        # registration challenge can never be swapped in here and vice versa.
        # Who the user turns out to be is resolved from the credential itself
        # in /complete, not from here.
        session['login_challenge'] = {
            'challenge': bytes_to_base64url(options.challenge),
            'expires_at': time.time() + CHALLENGE_TTL_SECONDS,
        }

        # Send JSON to frontend with sanitized transports
        return jsonify({
            'publicKey': {
                'challenge': bytes_to_base64url(options.challenge),
                'timeout': options.timeout,
                'rpId': options.rp_id,
                'allowCredentials': [
                    {
                        'id': bytes_to_base64url(cred.id),
                        'type': cred.type,
                        **({'transports': cred.transports} if cred.transports else {})
                    } for cred in options.allow_credentials
                ],
                'userVerification': options.user_verification
            }
        })

    except Exception:
        app.logger.exception('Login begin error')
        return jsonify({'error': AUTHENTICATION_FAILED}), 400


def verify_assertion(data, challenge_key):
    """Shared assertion check for login and step-up re-auth. Returns the stored
    credential row, or None if anything about the assertion doesn't hold up.
    Raises on a bad signature (py_webauthn's own failure mode)."""
    # Build AuthenticationCredential manually from browser JSON
    raw_id_bytes = base64url_to_bytes(data.get('rawId'))
    auth_data = base64url_to_bytes(data.get('response', {}).get('authenticatorData'))
    signature = base64url_to_bytes(data.get('response', {}).get('signature'))
    client_data = base64url_to_bytes(data.get('response', {}).get('clientDataJSON'))
    user_handle = data.get('response', {}).get('userHandle')
    user_handle_bytes = base64url_to_bytes(user_handle) if user_handle else None

    assertion_response = AuthenticatorAssertionResponse(
        client_data_json=client_data,
        authenticator_data=auth_data,
        signature=signature,
        user_handle=user_handle_bytes
    )

    credential = AuthenticationCredential(
        id=data.get('id'),
        raw_id=raw_id_bytes,
        response=assertion_response,
        authenticator_attachment=data.get('authenticatorAttachment'),
        type=data.get('type')
    )

    # Single-use: popped up front so a replayed assertion can't reuse it. The
    # key is ceremony-specific, so a login challenge can't satisfy a step-up
    # (or a registration) and vice versa.
    pending = session.pop(challenge_key, None)
    if not pending or pending.get('expires_at', 0) < time.time():
        return None
    challenge = base64url_to_bytes(pending['challenge'])

    # Get stored credential
    credential_id = base64.b64encode(credential.raw_id).decode()
    stored_credential = get_credential_by_id(credential_id)
    if not stored_credential:
        return None

    # Verify authentication response. require_user_verification is the server
    # -side half of "biometric required": without it py_webauthn accepts an
    # assertion whose UV flag is clear, i.e. mere possession of the key.
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=base64.b64decode(stored_credential['public_key']),
        credential_current_sign_count=stored_credential['sign_count'],
        require_user_verification=True
    )

    # Persist the authenticator's new counter — without this, a cloned
    # authenticator replaying an old signature would never be detected.
    update_sign_count(credential_id, verification.new_sign_count)
    return stored_credential


@app.route('/api/login/complete', methods=['POST'])
@limiter.limit('20 per minute')
def login_complete():
    try:
        stored_credential = verify_assertion(request.get_json(silent=True) or {}, 'login_challenge')
        if not stored_credential:
            return jsonify({'error': AUTHENTICATION_FAILED}), 400

        # Resolve the user from the credential itself (not from session state
        # set during /begin) so this works for both the normal email-first
        # login and the emailless conditional-UI/autofill login.
        user = get_user_by_id(stored_credential['user_id'])
        if not user:
            return jsonify({'error': AUTHENTICATION_FAILED}), 400

        establish_session(user['id'], user['email'], user['session_epoch'])

        app.logger.info('Login completed')
        return jsonify({'verified': True})

    except Exception:
        app.logger.exception('Login verification failed')
        return jsonify({'error': AUTHENTICATION_FAILED}), 400


@app.route('/api/stepup/begin', methods=['POST'])
@limiter.limit('15 per minute')
def stepup_begin():
    """Re-authentication for an already-signed-in session, ahead of adding a
    new passkey. Deliberately separate from /api/login/*: it grants no new
    identity, so it must not be able to consume or produce a login challenge."""
    user = current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64.b64decode(cred['credential_id']))
            for cred in get_user_credentials(user['id'])
        ],
        user_verification=UserVerificationRequirement.REQUIRED
    )

    session['stepup_challenge'] = {
        'challenge': bytes_to_base64url(options.challenge),
        'expires_at': time.time() + CHALLENGE_TTL_SECONDS,
    }

    return jsonify({
        'publicKey': {
            'challenge': bytes_to_base64url(options.challenge),
            'timeout': options.timeout,
            'rpId': options.rp_id,
            'allowCredentials': [
                {
                    'id': bytes_to_base64url(cred.id),
                    'type': cred.type,
                    **({'transports': cred.transports} if cred.transports else {})
                } for cred in options.allow_credentials
            ],
            'userVerification': options.user_verification
        }
    })


@app.route('/api/stepup/complete', methods=['POST'])
@limiter.limit('20 per minute')
def stepup_complete():
    user = current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    try:
        stored_credential = verify_assertion(request.get_json(silent=True) or {}, 'stepup_challenge')
        # The assertion has to come from a passkey of THIS account — any valid
        # assertion would otherwise re-arm the step-up for whoever holds the
        # session cookie.
        if not stored_credential or stored_credential['user_id'] != user['id']:
            return jsonify({'error': AUTHENTICATION_FAILED}), 400

        session['stepup_at'] = time.time()
        return jsonify({'verified': True})

    except Exception:
        app.logger.exception('Step-up verification failed')
        return jsonify({'error': AUTHENTICATION_FAILED}), 400


@app.route('/api/login/recovery', methods=['POST'])
@limiter.limit('5 per minute')
def login_recovery():
    try:
        data = request.get_json(silent=True) or {}
        email = data.get('email')
        code = data.get('code')

        if not email or not code:
            return jsonify({'error': RECOVERY_FAILED}), 400

        user = consume_recovery_code(email, code)
        if not user:
            return jsonify({'error': RECOVERY_FAILED}), 400

        establish_session(user['id'], user['email'], user['session_epoch'])

        # One used code invalidates the whole set: anyone who saw the printed
        # list (the usual way these leak) must not keep a spare way in.
        return jsonify({'verified': True, 'recoveryCodes': generate_recovery_codes(user['id'])})

    except Exception:
        app.logger.exception('Recovery login failed')
        return jsonify({'error': RECOVERY_FAILED}), 400


@app.route('/api/devices')
@limiter.limit('60 per minute')
def list_devices():
    user = current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    creds = get_user_credentials(user['id'])
    return jsonify({'devices': [
        {
            'credentialId': c['credential_id'],
            'deviceName': c['device_name'] or 'Unnamed device',
            'createdAt': c['created_at'].isoformat() if c['created_at'] else None,
            'lastUsedAt': c['last_used_at'].isoformat() if c['last_used_at'] else None,
        } for c in creds
    ]})


@app.route('/api/devices/<path:credential_id>/rename', methods=['POST'])
@limiter.limit('30 per minute')
def rename_device(credential_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Name is required'}), 400

    if not rename_credential(user['id'], credential_id, name):
        return jsonify({'error': 'Device not found'}), 404
    return jsonify({'success': True})


@app.route('/api/devices/<path:credential_id>', methods=['DELETE'])
@limiter.limit('30 per minute')
def revoke_device(credential_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    if not delete_credential(user['id'], credential_id):
        return jsonify({'error': "Can't remove your last remaining device"}), 400

    # Revoking a device is what you do when one is lost or stolen, so any
    # session it left behind has to die with it. This session just proved it
    # is the one doing the revoking, so it re-pins the new epoch and stays
    # signed in (in place — no clear, so the open page keeps its CSRF token).
    new_epoch = bump_session_epoch(user['id'])
    session['session_epoch'] = new_epoch
    session.pop('stepup_at', None)
    return jsonify({'success': True})


if __name__ == '__main__':
    # debug must never default to on: the Werkzeug debugger is remote code
    # execution for anyone who can reach it.
    app.run(debug=DEBUG, host=os.environ.get('HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', 5000)))
