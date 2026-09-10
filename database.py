import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta

from models import Credential, RecoveryCode, User, db


def init_db(app):
    default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'securepass.db')
    db_path = os.environ.get('DATABASE_PATH', default_path)
    app.config.setdefault('SQLALCHEMY_DATABASE_URI', f'sqlite:///{db_path}')
    app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', False)
    _set_code_pepper(app.secret_key)
    db.init_app(app)
    with app.app_context():
        db.create_all()
        _migrate_legacy_columns()


def _migrate_legacy_columns():
    """Add columns introduced after the original hand-written sqlite3 schema,
    without touching rows already in an existing database file."""
    inspector = db.inspect(db.engine)
    tables = inspector.get_table_names()
    if 'credentials' in tables:
        columns = {c['name'] for c in inspector.get_columns('credentials')}
        with db.engine.begin() as conn:
            if 'device_name' not in columns:
                conn.execute(db.text('ALTER TABLE credentials ADD COLUMN device_name TEXT'))
            if 'last_used_at' not in columns:
                conn.execute(db.text('ALTER TABLE credentials ADD COLUMN last_used_at DATETIME'))
    if 'recovery_codes' in tables:
        columns = {c['name'] for c in inspector.get_columns('recovery_codes')}
        if 'code_index' not in columns:
            with db.engine.begin() as conn:
                conn.execute(db.text('ALTER TABLE recovery_codes ADD COLUMN code_index TEXT'))
                # The index can't be backfilled — it's derived from the code
                # itself, and only the (irreversible) hash was ever stored.
                orphans = conn.execute(db.text(
                    'SELECT count(*) FROM recovery_codes WHERE used_at IS NULL')).scalar()
                if orphans:
                    print(f'WARNING: {orphans} recovery code(s) predate the lookup index and can no '
                          'longer be redeemed. Affected users must sign in with a passkey to get a '
                          'fresh set.')
    if 'users' in tables:
        columns = {c['name'] for c in inspector.get_columns('users')}
        with db.engine.begin() as conn:
            if 'session_epoch' not in columns:
                conn.execute(db.text('ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0'))
            if 'recovery_failures' not in columns:
                conn.execute(db.text('ALTER TABLE users ADD COLUMN recovery_failures INTEGER NOT NULL DEFAULT 0'))
            if 'recovery_locked_until' not in columns:
                conn.execute(db.text('ALTER TABLE users ADD COLUMN recovery_locked_until DATETIME'))
            # Emails are stored lowercase now; fold any legacy mixed-case rows
            # so those accounts stay reachable. A collision means two accounts
            # already differ only by case — leave them alone and log it.
            try:
                conn.execute(db.text('UPDATE users SET email = lower(email) WHERE email <> lower(email)'))
            except Exception as exc:  # pragma: no cover - only on colliding legacy data
                print(f'WARNING: could not lowercase legacy emails: {exc}')


def normalize_email(email):
    """One canonical form for lookups and storage, so 'Foo@Example.com' and
    'foo@example.com' can't become two accounts (or dodge a taken-email check)."""
    return (email or '').strip().lower()


def _user_to_dict(user):
    return {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'created_at': user.created_at,
        'session_epoch': user.session_epoch or 0,
    }


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


def create_user_with_credential(user_id, name, email, credential, recovery_code_count=8):
    """Signup as ONE transaction: user row, first credential and recovery codes
    commit together or not at all. Three separate commits could be interrupted
    in between and leave a user row squatting an email with no usable
    credential and no recovery path. Returns the plaintext recovery codes, or
    None if the id/email is already taken."""
    email = normalize_email(email)
    try:
        if db.session.get(User, user_id) or User.query.filter_by(email=email).first():
            return None
        db.session.add(User(id=user_id, name=name, email=email))
        db.session.add(Credential(user_id=user_id, **credential))
        codes = _add_recovery_codes(user_id, recovery_code_count)
        db.session.commit()
        return codes
    except Exception:
        # Includes the unique-email constraint firing on a concurrent signup.
        db.session.rollback()
        raise


def get_user_by_email(email):
    user = User.query.filter_by(email=normalize_email(email)).first()
    return _user_to_dict(user) if user else None


def bump_session_epoch(user_id):
    """Invalidates every session issued for this user so far. Returns the new
    epoch so the caller can keep its own (just re-authenticated) session."""
    user = db.session.get(User, user_id)
    if not user:
        return None
    user.session_epoch = (user.session_epoch or 0) + 1
    db.session.commit()
    return user.session_epoch


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

# Server-side pepper for the recovery-code lookup index, set from the app's
# SECRET_KEY in init_db(). Peppering matters: the index is a single fast hash,
# so without a secret the DB alone would let an attacker brute-force the
# ~48-bit codes offline, sidestepping PBKDF2 entirely.
_code_pepper = None

# Per-account throttle, on top of the per-IP rate limit (which a distributed
# guessing run against one account would otherwise walk straight past).
_RECOVERY_MAX_FAILURES = 5
_RECOVERY_LOCKOUT = timedelta(minutes=15)


def _set_code_pepper(secret):
    global _code_pepper
    if not secret:
        raise RuntimeError('init_db() needs app.secret_key set first — it peppers recovery codes.')
    _code_pepper = secret.encode() if isinstance(secret, str) else bytes(secret)


def _code_index(user_id, normalized_code):
    """Deterministic lookup handle for one code, so redeeming is a single
    indexed row fetch instead of a scan that PBKDF2-verifies every unused code
    in turn (which leaked, via response time, both how many codes an account
    has left and how far down the list a guess landed)."""
    return hmac.new(_code_pepper, f'{user_id}:{normalized_code}'.encode(), hashlib.sha256).hexdigest()


def _add_recovery_codes(user_id, count):
    """Queues `count` fresh codes on the caller's open transaction (no commit,
    so signup can write user + credential + codes atomically). Returns the
    plaintext codes; only the salted KDF hash and the peppered index persist."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(6)  # 12 hex chars, ~48 bits
        codes.append(f'{raw[0:4]}-{raw[4:8]}-{raw[8:12]}')
        db.session.add(RecoveryCode(
            user_id=user_id,
            code_hash=_hash_code(raw),
            code_index=_code_index(user_id, raw),
        ))
    return codes


def generate_recovery_codes(user_id, count=8):
    """Replaces every existing code for the user and returns the new plaintext
    codes (shown to the user exactly once); only salted KDF hashes are
    persisted."""
    RecoveryCode.query.filter_by(user_id=user_id).delete()
    codes = _add_recovery_codes(user_id, count)
    db.session.commit()
    return codes


def _recovery_locked(user):
    return bool(user.recovery_locked_until and user.recovery_locked_until > datetime.utcnow())


def _register_recovery_failure(user):
    user.recovery_failures = (user.recovery_failures or 0) + 1
    if user.recovery_failures >= _RECOVERY_MAX_FAILURES:
        user.recovery_locked_until = datetime.utcnow() + _RECOVERY_LOCKOUT
    db.session.commit()


def consume_recovery_code(email, code):
    """Verifies a one-time recovery code and marks it used. Returns the user
    dict on success, None otherwise.

    Every call costs exactly one index HMAC plus one PBKDF2 verification —
    unknown email, locked account, wrong code and right code all do the same
    work, so the response time says nothing about any of them."""
    normalized = _normalize_code(code)
    user = User.query.filter_by(email=normalize_email(email)).first()

    candidate = None
    if user and not _recovery_locked(user):
        candidate = RecoveryCode.query.filter_by(
            user_id=user.id,
            code_index=_code_index(user.id, normalized),
            used_at=None,
        ).first()

    if not _verify_code(normalized, candidate.code_hash if candidate else _DUMMY_HASH):
        if user:
            _register_recovery_failure(user)
        return None

    candidate.used_at = datetime.utcnow()
    user.recovery_failures = 0
    user.recovery_locked_until = None
    db.session.commit()
    return _user_to_dict(user)
