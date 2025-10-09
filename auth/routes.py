from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    UserVerificationRequirement,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
)
import base64
import json

# Import the same database helpers used in app.py
from database import get_user_by_email, get_user_credentials, get_credential_by_id

auth_bp = Blueprint('auth', __name__)

# WebAuthn configuration (match app.py)
RP_ID = "localhost"
ORIGIN = "http://localhost:5000"


@auth_bp.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@auth_bp.route('/api/login/begin', methods=['POST'])
def login_begin():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Get user and their credentials
        user = get_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        credentials = get_user_credentials(user['id'])
        if not credentials:
            return jsonify({'error': 'No credentials found for user'}), 404

        # Create allow credentials list
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64.b64decode(cred['credential_id']))
            for cred in credentials
        ]

        # Generate authentication options
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        # Store challenge and user info in session
        session['challenge'] = base64.b64encode(options.challenge).decode()
        session['user_id'] = user['id']
        session['user_email'] = email

        # Send JSON to frontend with sanitized transports
        return jsonify({
            'publicKey': {
                'challenge': base64.b64encode(options.challenge).decode(),
                'timeout': options.timeout,
                'rpId': options.rp_id,
                'allowCredentials': [
                    {
                        'id': base64.b64encode(cred.id).decode(),
                        'type': cred.type,
                        **({'transports': cred.transports} if cred.transports else {}),
                    }
                    for cred in options.allow_credentials
                ],
                'userVerification': options.user_verification,
            }
        })

    except Exception as e:
        print(f"Login begin error: {e}")
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/api/login/complete', methods=['POST'])
def login_complete():
    try:
        data = request.get_json()
        credential = AuthenticationCredential.parse_raw(json.dumps(data))

        challenge = base64.b64decode(session.get('challenge', ''))
        user_id = session.get('user_id')
        user_email = session.get('user_email')

        if not challenge or not user_id:
            return jsonify({'error': 'Invalid session'}), 400

        # Get stored credential
        credential_id = base64.b64encode(credential.raw_id).decode()
        stored_credential = get_credential_by_id(credential_id)
        if not stored_credential:
            return jsonify({'error': 'Credential not found'}), 404

        # Verify authentication response
        verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64.b64decode(stored_credential['public_key']),
            credential_current_sign_count=stored_credential['sign_count'],
        )

        # If no exception, login succeeded
        session['user_id'] = user_id
        session['user_email'] = user_email
        session['authenticated'] = True

        print(f"Login completed for user: {user_email}")
        return jsonify({'verified': True})

    except Exception as e:
        print(f"Login verification failed: {e}")
        return jsonify({'error': str(e)}), 400
