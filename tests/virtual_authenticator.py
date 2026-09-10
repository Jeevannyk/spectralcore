"""
Software WebAuthn authenticator for tests.

py_webauthn (the `webauthn` package) only implements the relying-party
(verification) side of the spec, not a client/authenticator. To exercise the
real register -> login round trip without a physical fingerprint/security
key, this builds valid CBOR attestation/assertion objects and signs them
with a real EC keypair, exactly as a browser + authenticator would.
"""
import base64
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

UP = 0x01  # user present
UV = 0x04  # user verified
AT = 0x40  # attested credential data included


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def b64url_decode(s: str) -> bytes:
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


class VirtualAuthenticator:
    """One simulated security key. Holds one keypair per (rp_id, credential)."""

    def __init__(self):
        self._keys = {}  # credential_id (bytes) -> ec.EllipticCurvePrivateKey
        self._sign_counts = {}

    def _rp_id_hash(self, rp_id: str) -> bytes:
        return hashlib.sha256(rp_id.encode()).digest()

    def create_credential(self, rp_id: str, challenge_b64url: str, origin: str,
                          user_verified: bool = True):
        """Simulates navigator.credentials.create() -> returns the JSON body
        the browser would POST to /api/register/complete.

        user_verified=False models an authenticator (or a patched client) that
        skipped the biometric/PIN and only set the "user present" flag."""
        credential_id = os.urandom(32)
        private_key = ec.generate_private_key(ec.SECP256R1())
        self._keys[credential_id] = private_key
        self._sign_counts[credential_id] = 1

        pub_numbers = private_key.public_key().public_numbers()
        x = pub_numbers.x.to_bytes(32, 'big')
        y = pub_numbers.y.to_bytes(32, 'big')
        cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}  # EC2 / ES256 / P-256

        flags = UP | AT | (UV if user_verified else 0)
        auth_data = (
            self._rp_id_hash(rp_id)
            + bytes([flags])
            + (1).to_bytes(4, 'big')
            + b'\x00' * 16  # aaguid
            + len(credential_id).to_bytes(2, 'big')
            + credential_id
            + cbor2.dumps(cose_key)
        )

        attestation_object = cbor2.dumps({
            'fmt': 'none',
            'attStmt': {},
            'authData': auth_data,
        })

        client_data = json.dumps({
            'type': 'webauthn.create',
            'challenge': challenge_b64url,
            'origin': origin,
            'crossOrigin': False,
        }).encode()

        return {
            'id': b64url(credential_id),
            'rawId': b64url(credential_id),
            'type': 'public-key',
            'authenticatorAttachment': 'cross-platform',
            'response': {
                'attestationObject': b64url(attestation_object),
                'clientDataJSON': b64url(client_data),
            },
        }

    def get_assertion(self, rp_id: str, challenge_b64url: str, origin: str,
                       credential_id: bytes, user_handle: bytes,
                       user_verified: bool = True, sign_count: int = None):
        """Simulates navigator.credentials.get().

        user_verified=False models an authenticator that never checked the
        user (only presence); sign_count forces a specific counter value, e.g.
        to replay an old one the way a cloned authenticator would."""
        private_key = self._keys[credential_id]
        self._sign_counts[credential_id] += 1
        if sign_count is None:
            sign_count = self._sign_counts[credential_id]

        flags = UP | (UV if user_verified else 0)
        auth_data = (
            self._rp_id_hash(rp_id)
            + bytes([flags])
            + sign_count.to_bytes(4, 'big')
        )

        client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': challenge_b64url,
            'origin': origin,
            'crossOrigin': False,
        }).encode()

        signed_data = auth_data + hashlib.sha256(client_data).digest()
        der_signature = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

        return {
            'id': b64url(credential_id),
            'rawId': b64url(credential_id),
            'type': 'public-key',
            'response': {
                'authenticatorData': b64url(auth_data),
                'clientDataJSON': b64url(client_data),
                'signature': b64url(der_signature),
                'userHandle': b64url(user_handle),
            },
        }
