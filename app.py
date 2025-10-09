from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import secrets
import base64
import json
from database import init_db, create_user, get_user_by_email, add_credential, get_user_credentials, get_credential_by_id

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# WebAuthn configuration
RP_ID = "localhost"
RP_NAME = "SecurePass"
ORIGIN = "http://localhost:5000"

# Initialize database
init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('auth/register.html')

# Register auth blueprint and remove local /login in favor of auth routes
try:
    from auth.routes import auth_bp
    app.register_blueprint(auth_bp)
except Exception as e:
    print(f"Warning: failed to register auth blueprint: {e}")

@app.route('/dashboard')
def dashboard():
    # Enhanced session validation
    if 'user_id' not in session or 'user_email' not in session:
        print("Dashboard access denied: Missing session data")
        session.clear()  # Clear any partial session data
        return redirect(url_for('index'))
    
    # Get user from database with error handling
    user = get_user_by_email(session['user_email'])
    if not user:
        print(f"Dashboard access denied: User not found for email {session['user_email']}")
        session.clear()  # Clear invalid session
        return redirect(url_for('index'))
    
    # Verify session user_id matches database user_id
    if session['user_id'] != user['id']:
        print(f"Dashboard access denied: Session user_id mismatch")
        session.clear()  # Clear invalid session
        return redirect(url_for('index'))
    
    # Get user credentials with error handling
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

@app.route('/api/register/begin', methods=['POST'])
def register_begin():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        
        if not name or not email:
            return jsonify({'error': 'Name and email are required'}), 400
        
        # Check if user already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            user_id = existing_user['id']
            user_credentials = get_user_credentials(user_id)
            exclude_credentials = [
                PublicKeyCredentialDescriptor(id=base64.b64decode(cred['credential_id']))
                for cred in user_credentials
            ]
        else:
            user_id = secrets.token_hex(32)
            exclude_credentials = []
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,  # Fixed: removed .encode() since user_id is already a string
            user_name=email,
            user_display_name=name,
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ]
        )
        
        # Store challenge in session
        session['challenge'] = base64.b64encode(options.challenge).decode()
        session['user_id'] = user_id
        session['user_name'] = name
        session['user_email'] = email
        
        return jsonify({
            'publicKey': {
                'challenge': base64.b64encode(options.challenge).decode(),
                'rp': {'id': options.rp.id, 'name': options.rp.name},
                'user': {
                    'id': base64.b64encode(options.user.id).decode(),
                    'name': options.user.name,
                    'displayName': options.user.display_name
                },
                'pubKeyCredParams': [{'alg': alg.alg, 'type': 'public-key'} for alg in options.pub_key_cred_params],
                'timeout': options.timeout,
                'excludeCredentials': [
                    {
                        'id': base64.b64encode(cred.id).decode(),
                        'type': cred.type,
                        'transports': cred.transports
                    } for cred in options.exclude_credentials
                ] if options.exclude_credentials else [],
                'authenticatorSelection': {
                    'authenticatorAttachment': options.authenticator_selection.authenticator_attachment,
                    'requireResidentKey': options.authenticator_selection.require_resident_key,
                    'userVerification': options.authenticator_selection.user_verification
                },
                'attestation': options.attestation
            }
        })
    except Exception as e:
        print(f"Registration begin error: {e}")  # Added logging
        return jsonify({'error': str(e)}), 500

@app.route('/api/register/complete', methods=['POST'])
def register_complete():
    try:
        data = request.get_json()
        credential = RegistrationCredential.parse_raw(json.dumps(data))

        # Get session data
        challenge = base64.b64decode(session.get('challenge', ''))
        user_id = session.get('user_id')
        user_name = session.get('user_name')
        user_email = session.get('user_email')

        if not challenge or not user_id:
            return jsonify({'error': 'Invalid session'}), 400

        # Verify registration response
        # If verification fails, it will raise an exception
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )

        # Create user if doesn't exist
        existing_user = get_user_by_email(user_email)
        if not existing_user:
            create_user(user_id, user_name, user_email)
            print(f"Created new user: {user_email} with ID: {user_id}")
        else:
            print(f"User already exists: {user_email}")

        # Store credential in database
        add_credential(
            user_id,
            base64.b64encode(verification.credential_id).decode(),
            base64.b64encode(verification.credential_public_key).decode(),
            verification.sign_count,
            credential.response.client_data_json,
            credential.response.attestation_object
        )

        # Set session for authenticated user
        session['user_id'] = user_id
        session['user_email'] = user_email
        session['authenticated'] = True

        print(f"Registration completed for user: {user_email}")
        return jsonify({'verified': True})

    except Exception as e:
        print(f"Registration verification failed: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/login/begin', methods=['POST'])
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
            user_verification=UserVerificationRequirement.REQUIRED
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
                        **({'transports': cred.transports} if cred.transports else {})
                    } for cred in options.allow_credentials
                ],
                'userVerification': options.user_verification
            }
        })

    except Exception as e:
        print(f"Login begin error: {e}")  # Logging
        return jsonify({'error': str(e)}), 500


@app.route('/api/login/complete', methods=['POST'])
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
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64.b64decode(stored_credential['public_key']),
            credential_current_sign_count=stored_credential['sign_count']
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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)