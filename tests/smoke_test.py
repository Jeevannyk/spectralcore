"""Quick manual smoke check of the two /begin endpoints. Uses a throwaway
temp database and fake addresses — never the real securepass.db.

Run: venv/Scripts/python.exe tests/smoke_test.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

_tmp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
_tmp_db.close()
os.environ['DATABASE_PATH'] = _tmp_db.name
os.environ.setdefault('SECRET_KEY', 'test-secret-key')

from app import app  # noqa: E402  (must import after env vars are set)

client = app.test_client()


def csrf():
    client.get('/login')
    with client.session_transaction() as sess:
        return sess.get('csrf_token', '')


def post(url, payload):
    return client.post(url, json=payload, headers={'X-CSRF-Token': csrf()})


print('POST /api/register/begin')
resp = post('/api/register/begin', {'name': 'Test User', 'email': 'test@example.com'})
print('Status:', resp.status_code)
print('Body:', json.dumps(resp.get_json(), indent=2))

print('\nPOST /api/login/begin (unknown user)')
resp2 = post('/api/login/begin', {'email': 'test@example.com'})
print('Status:', resp2.status_code)
print('Body:', json.dumps(resp2.get_json(), indent=2))

print('\nPOST /api/login/begin (no email — conditional UI)')
resp3 = post('/api/login/begin', {})
print('Status:', resp3.status_code)
print('Body:', json.dumps(resp3.get_json(), indent=2)[:2000])

try:
    os.unlink(_tmp_db.name)
except OSError:
    pass  # Windows keeps the sqlite file locked while the pooled connection is open
