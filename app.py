import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import timedelta

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
    create_user,
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

app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    print('WARNING: SECRET_KEY is not set — using a random key for this process only. '
          'Every restart will invalidate all existing sessions. Set the SECRET_KEY '
          'environment variable for a real deployment.')

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
)

# A WebAuthn ceremony that isn't finished within this window has to restart.
CHALLENGE_TTL_SECONDS = 300

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
    return {'csrf_token': session.get('csrf_token') or _new_csrf_token()}


def establish_session(user_id, user_email):
    """Called ONLY after a completed, verified ceremony. Clears everything
    first so a pre-auth session can never be upgraded in place (session
    fixation), and mints a fresh CSRF token."""
    session.clear()
    session.permanent = True
    session['user_id'] = user_id
    session['user_email'] = user_email
    session['authenticated'] = True
    _new_csrf_token()


def decoy_credential_id(email: str) -> bytes:
    """A stable, unguessable 32-byte id for an email we have no passkey for,
    so /api/login/begin answers unknown and known accounts identically."""
    return hmac.new(app.secret_key.encode() if isinstance(app.secret_key, str) else app.secret_key,
                    f'decoy:{email}'.encode(), hashlib.sha256).digest()


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
        #   * no session -> brand new signup, and an email that already
        #     exists is rejected outright (matching an email is not proof of
        #     owning the account).
        user = current_user()
        if user:
            mode = 'add_device'
            user_id, name, email = user['id'], user['name'], user['email']
            exclude_credentials = [
                PublicKeyCredentialDescriptor(id=base64.b64decode(cred['credential_id']))
                for cred in get_user_credentials(user_id)
            ]
        else:
            mode = 'signup'
            name = data.get('name')
            email = data.get('email')
            if not name or not email:
                return jsonify({'error': 'Name and email are required'}), 400
            if get_user_by_email(email):
                return jsonify({'error': REGISTRATION_FAILED}), 400
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

        if is_new_user:
            # Re-check: someone may have signed up with this email while the
            # ceremony was in flight.
            if get_user_by_email(user_email):
                return jsonify({'error': REGISTRATION_FAILED}), 400
        else:
            # Adding a device requires the session to still belong to exactly
            # the account the ceremony was started for.
            session_user = current_user()
            if not session_user or session_user['id'] != user_id:
                return jsonify({'error': 'Not authenticated'}), 401

        # Verify registration response
        # If verification fails, it will raise an exception
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )

        if is_new_user and not create_user(user_id, user_name, user_email):
            return jsonify({'error': REGISTRATION_FAILED}), 400

        # Store credential in database
        # Ensure binary fields are stored as base64 strings in the database
        client_data_b64 = (credential.response.client_data_json
                           if isinstance(credential.response.client_data_json, str)
                           else base64.b64encode(credential.response.client_data_json).decode())
        attestation_b64 = (credential.response.attestation_object
                           if isinstance(credential.response.attestation_object, str)
                           else base64.b64encode(credential.response.attestation_object).decode())

        device_name = guess_device_name(request.headers.get('User-Agent', ''), credential.authenticator_attachment)

        add_credential(
            user_id,
            base64.b64encode(verification.credential_id).decode(),
            base64.b64encode(verification.credential_public_key).decode(),
            verification.sign_count,
            client_data_b64,
            attestation_b64,
            device_name=device_name
        )

        # Verified ceremony — only now does this session get an identity.
        # (Add-device already runs in an authenticated session; re-establishing
        # it would needlessly rotate the CSRF token of the open page.)
        if is_new_user:
            establish_session(user_id, user_email)

        response = {'verified': True}
        if is_new_user:
            # Shown to the user exactly once — WebAuthn has no password reset,
            # so a lost/broken authenticator needs a backup way in.
            response['recoveryCodes'] = generate_recovery_codes(user_id)

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
        email = data.get('email')

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
                # -enumeration oracle. The decoy id is derived from the email
                # so probing the same address twice gives the same answer.
                allow_credentials = [PublicKeyCredentialDescriptor(id=decoy_credential_id(email))]
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


@app.route('/api/login/complete', methods=['POST'])
@limiter.limit('20 per minute')
def login_complete():
    try:
        data = request.get_json(silent=True) or {}
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

        # Single-use: popped up front so a replayed assertion can't reuse it.
        pending = session.pop('login_challenge', None)
        if not pending or pending.get('expires_at', 0) < time.time():
            return jsonify({'error': AUTHENTICATION_FAILED}), 400
        challenge = base64url_to_bytes(pending['challenge'])

        # Get stored credential
        credential_id = base64.b64encode(credential.raw_id).decode()
        stored_credential = get_credential_by_id(credential_id)
        if not stored_credential:
            return jsonify({'error': AUTHENTICATION_FAILED}), 400

        # Verify authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64.b64decode(stored_credential['public_key']),
            credential_current_sign_count=stored_credential['sign_count']
        )

        # Persist the authenticator's new counter — without this, a cloned
        # authenticator replaying an old signature would never be detected.
        update_sign_count(credential_id, verification.new_sign_count)

        # Resolve the user from the credential itself (not from session state
        # set during /begin) so this works for both the normal email-first
        # login and the emailless conditional-UI/autofill login.
        user = get_user_by_id(stored_credential['user_id'])
        if not user:
            return jsonify({'error': AUTHENTICATION_FAILED}), 400

        establish_session(user['id'], user['email'])

        app.logger.info('Login completed')
        return jsonify({'verified': True})

    except Exception:
        app.logger.exception('Login verification failed')
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

        establish_session(user['id'], user['email'])

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
    return jsonify({'success': True})


if __name__ == '__main__':
    # debug must never default to on: the Werkzeug debugger is remote code
    # execution for anyone who can reach it.
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    app.run(debug=debug, host=os.environ.get('HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', 5000)))
