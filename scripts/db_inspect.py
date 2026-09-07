#!/usr/bin/env python3
"""
Print a redacted summary of the local database (no full emails, no key
material). Override the location with DATABASE_PATH.
Run: python scripts/db_inspect.py
"""
import os
import sqlite3

DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'securepass.db')
DB = os.environ.get('DATABASE_PATH', DEFAULT_DB)


def mask_email(email):
    if not email or '@' not in str(email):
        return '<redacted>'
    local, _, domain = str(email).partition('@')
    return f'{local[:2]}***@{domain}'


def short(value, keep=12):
    text = str(value)
    return text if len(text) <= keep else f'{text[:keep]}...'


if not os.path.exists(DB):
    print('DB not found:', DB)
    raise SystemExit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

print('Users:')
try:
    for uid, name, email, created_at in cur.execute('SELECT id, name, email, created_at FROM users'):
        print((short(uid), short(name, 1) + '***', mask_email(email), created_at))
except Exception as e:
    print('Users query error:', e)

print('\nCredentials:')
try:
    for cid, user_id, credential_id, sign_count, created_at in cur.execute(
            'SELECT id, user_id, credential_id, sign_count, created_at FROM credentials'):
        print((cid, short(user_id), short(credential_id), sign_count, created_at))
except Exception as e:
    print('Credentials query error:', e)

conn.close()
