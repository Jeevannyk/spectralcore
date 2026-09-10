from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Text, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Embedded in every session cookie and re-checked on each request, so
    # bumping it (logout, device revoke) kills sessions server-side.
    session_epoch = db.Column(db.Integer, nullable=False, default=0)
    # Per-account recovery-code throttle (the IP limiter alone doesn't stop a
    # distributed guessing run against one account).
    recovery_failures = db.Column(db.Integer, nullable=False, default=0)
    recovery_locked_until = db.Column(db.DateTime)

    credentials = db.relationship('Credential', backref='user', lazy=True, cascade='all, delete-orphan')
    recovery_codes = db.relationship('RecoveryCode', backref='user', lazy=True, cascade='all, delete-orphan')


class Credential(db.Model):
    __tablename__ = 'credentials'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Text, db.ForeignKey('users.id'), nullable=False)
    credential_id = db.Column(db.Text, unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    client_data_json = db.Column(db.Text)
    attestation_object = db.Column(db.Text)
    device_name = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime)


class RecoveryCode(db.Model):
    __tablename__ = 'recovery_codes'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Text, db.ForeignKey('users.id'), nullable=False)
    code_hash = db.Column(db.Text, nullable=False)
    # Peppered HMAC of (user_id, code): lets redemption fetch the one candidate
    # row directly instead of PBKDF2-ing its way down the whole list.
    code_index = db.Column(db.Text, index=True)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
