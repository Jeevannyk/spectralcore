#!/usr/bin/env python3
"""
Normalize securepass.db user_id storage:
- Convert any BLOB (bytes) user.id values into text (utf-8 or hex fallback)
- Update credentials.user_id to the new value
Run: python scripts/normalize_db.py
"""
import sqlite3
import os

DB = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'securepass.db')

if not os.path.exists(DB):
    print('DB not found:', DB)
    raise SystemExit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

# Find users where id is returned as bytes
cur.execute('SELECT rowid, id FROM users')
rows = cur.fetchall()

changes = []
for row in rows:
    rowid, uid = row
    if isinstance(uid, (bytes, bytearray)):
        # Try UTF-8 decode
        try:
            new_id = uid.decode('utf-8')
        except Exception:
            new_id = uid.hex()
        changes.append((rowid, uid, new_id))

if not changes:
    print('No user id blobs found. No changes needed.')
    conn.close()
    raise SystemExit(0)

print('Found', len(changes), 'user id(s) to normalize')
for rowid, old, new in changes:
    print('Row', rowid, 'old:', old, '-> new:', new)

# Apply updates in a transaction
try:
    for rowid, old, new in changes:
        # Check for collision
        cur.execute('SELECT id FROM users WHERE id = ?', (new,))
        if cur.fetchone():
            raise RuntimeError(f'Collision: target id {new} already exists in users')
        # Update credentials referencing old id
        cur.execute('UPDATE credentials SET user_id = ? WHERE user_id = ?', (new, old))
        # Update users id
        cur.execute('UPDATE users SET id = ? WHERE rowid = ?', (new, rowid))
    conn.commit()
    print('Normalization complete, committed changes.')
except Exception as e:
    conn.rollback()
    print('Error during normalization, rolled back:', e)
finally:
    conn.close()
