import sqlite3
import os

DATABASE = 'securepass.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create credentials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            credential_id TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER DEFAULT 0,
            client_data_json TEXT,
            attestation_object TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def create_user(user_id, name, email):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO users (id, name, email) VALUES (?, ?, ?)',
            (user_id, name, email)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    return dict(user) if user else None

def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    return dict(user) if user else None

def add_credential(user_id, credential_id, public_key, sign_count, client_data_json, attestation_object):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO credentials 
        (user_id, credential_id, public_key, sign_count, client_data_json, attestation_object)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, credential_id, public_key, sign_count, client_data_json, attestation_object))
    
    conn.commit()
    conn.close()

def get_user_credentials(user_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM credentials WHERE user_id = ?', (user_id,))
    credentials = cursor.fetchall()
    conn.close()
    
    return [dict(cred) for cred in credentials]

def get_credential_by_id(credential_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM credentials WHERE credential_id = ?', (credential_id,))
    credential = cursor.fetchone()
    conn.close()
    
    return dict(credential) if credential else None

def update_sign_count(credential_id, new_sign_count):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'UPDATE credentials SET sign_count = ? WHERE credential_id = ?',
        (new_sign_count, credential_id)
    )
    
    conn.commit()
    conn.close()