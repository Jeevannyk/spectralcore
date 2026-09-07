import hashlib
import hmac
import os
import secrets
from datetime import datetime

from models import Credential, RecoveryCode, User, db


def init_db(app):
    default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'securepass.db')
    db_path = os.environ.get('DATABASE_PATH', default_path)
    app.config.setdefault('SQLALCHEMY_DATABASE_URI', f'sqlite:///{db_path}')
    app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', False)
    db.init_app(app)
    with app.app_context():
        db.create_all()
        _migrate_legacy_columns()


def _migrate_legacy_columns():
    """Add columns introduced after the original hand-written sqlite3 schema,
    without touching rows already in an existing database file."""
    inspector = db.inspect(db.engine)
    if 'credentials' not in inspector.get_table_names():
        return
    columns = {c['name'] for c in inspector.get_columns('credentials')}
    with db.engine.begin() as conn:
        if 'device_name' not in columns:
            conn.execute(db.text('ALTER TABLE credentials ADD COLUMN device_name TEXT'))
        if 'last_used_at' not in columns:
            conn.execute(db.text('ALTER TABLE credentials ADD COLUMN last_used_at DATETIME'))


def _user_to_dict(user):
    return {'id': user.id, 'name': user.name, 'email': user.email, 'created_at': user.created_at}


def _credential_to_dict(c):
    return {
        'id': c.id,
        'user_id': c.user_id,
        'credential_id': c.credential_id,
        'public_key': c.public_key,
        'sign_count': c.sign_count,
        'client_data_json': c.client_data_json,
        'attestation_object': c.attestation_object,
        'device_name': c.device_name,
        'created_at': c.created_at,
        'last_used_at': c.last_used_at,
    }


def create_user(user_id, name, email):
    if db.session.get(User, user_id) or User.query.filter_by(email=email).first():
        return False
    db.session.add(User(id=user_id, name=name, email=email))
    db.session.commit()
    return True


def get_user_by_email(email):
    user = User.query.filter_by(email=email).first()
    return _user_to_dict(user) if user else None


def get_user_by_id(user_id):
    user = db.session.get(User, user_id)
    return _user_to_dict(user) if user else None


def add_credential(user_id, credential_id, public_key, sign_count, client_data_json, attestation_object, device_name=None):
    if isinstance(user_id, (bytes, bytearray)):
        user_id = user_id.decode('utf-8')
    db.session.add(Credential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=sign_count,
        client_data_json=client_data_json,
        attestation_object=attestation_object,
        device_name=device_name,
    ))
    db.session.commit()


def get_user_credentials(user_id):
    if isinstance(user_id, (bytes, bytearray)):
        user_id = user_id.decode('utf-8')
    creds = Credential.query.filter_by(user_id=user_id).order_by(Credential.created_at.asc()).all()
    return [_credential_to_dict(c) for c in creds]


def get_credential_by_id(credential_id):
    c = Credential.query.filter_by(credential_id=credential_id).first()
    return _credential_to_dict(c) if c else None


def update_sign_count(credential_id, new_sign_count):
    c = Credential.query.filter_by(credential_id=credential_id).first()
    if not c:
        return
    c.sign_count = new_sign_count
    c.last_used_at = datetime.utcnow()
    db.session.commit()


def rename_credential(user_id, credential_id, device_name):
    c = Credential.query.filter_by(credential_id=credential_id, user_id=user_id).first()
    if not c:
        return False
    c.device_name = device_name.strip()[:255]
    db.session.commit()
    return True


def delete_credential(user_id, credential_id):
    c = Credential.query.filter_by(credential_id=credential_id, user_id=user_id).first()
    if not c:
        return False
    # keep at least one credential per user — otherwise the account is permanently locked out
    if Credential.query.filter_by(user_id=user_id).count() <= 1:
        return False
    db.session.delete(c)
    db.session.commit()
    return True


def _normalize_code(code):
    return code.strip().replace('-', '').replace(' ', '').lower()


_PBKDF2_ITERATIONS = 200_000


def _hash_code(code):
    """PBKDF2-HMAC-SHA256 with a per-code random salt, stored in a
    self-describing '<algo>$<iterations>$<salt>$<hash>' string so the
    parameters can be raised later without a schema change."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', code.encode(), salt, _PBKDF2_ITERATIONS)
    return f'pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}'


def _verify_code(code, stored):
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split('$')
        if algorithm != 'pbkdf2_sha256':
            return False
        digest = hashlib.pbkdf2_hmac('sha256', code.encode(), bytes.fromhex(salt_hex), int(iterations))
    except (AttributeError, ValueError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


# Verified against for unknown emails so a wrong address costs the same time
# as a wrong code (no timing oracle for account existence).
_DUMMY_HASH = _hash_code(secrets.token_hex(6))


def generate_recovery_codes(user_id, count=8):
    """Replaces every existing code for the user and returns the new plaintext
    codes (shown to the user exactly once); only salted KDF hashes are
    persisted."""
    RecoveryCode.query.filter_by(user_id=user_id).delete()
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(6)  # 12 hex chars, ~48 bits
        codes.append(f'{raw[0:4]}-{raw[4:8]}-{raw[8:12]}')
        db.session.add(RecoveryCode(user_id=user_id, code_hash=_hash_code(raw)))
    db.session.commit()
    return codes


def consume_recovery_code(email, code):
    """Verifies a one-time recovery code and marks it used. Returns the user
    dict on success, None otherwise."""
    normalized = _normalize_code(code)
    user = User.query.filter_by(email=email).first()
    if not user:
        _verify_code(normalized, _DUMMY_HASH)
        return None
    # Salts are per code, so there's nothing to look up by — each unused code
    # has to be checked.
    match = None
    for candidate in RecoveryCode.query.filter_by(user_id=user.id, used_at=None).all():
        if _verify_code(normalized, candidate.code_hash):
            match = candidate
            break
    if not match:
        return None
    match.used_at = datetime.utcnow()
    db.session.commit()
    return _user_to_dict(user)
