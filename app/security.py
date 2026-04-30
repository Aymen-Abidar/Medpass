import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .config import ACCESS_TOKEN_HOURS, ENCRYPTION_KEY, JWT_SECRET


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def hash_secret(secret: str, *, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt, iterations)
    return f'pbkdf2_sha256${iterations}${_b64u(salt)}${_b64u(digest)}'


def verify_secret(secret: str, stored: str) -> bool:
    try:
        algorithm, iterations_s, salt_b64, digest_b64 = stored.split('$', 3)
        if algorithm != 'pbkdf2_sha256':
            return False
        iterations = int(iterations_s)
        salt = base64.urlsafe_b64decode(salt_b64 + '==')
        expected = base64.urlsafe_b64decode(digest_b64 + '==')
        digest = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt, iterations)
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def create_token(payload: Dict[str, Any]) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_HOURS)
    payload = {**payload, 'exp': exp}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])


def _key_bytes() -> bytes:
    key = ENCRYPTION_KEY.encode('utf-8')
    if len(key) < 32:
        key = key.ljust(32, b'0')
    return key[:32]


def encrypt_text(plain_text: str) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain_text.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(_key_bytes()), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv).decode() + ':' + base64.b64encode(ciphertext).decode()


def decrypt_text(value: str) -> str:
    if not value:
        return '{}'
    iv_b64, ciphertext_b64 = value.split(':', 1)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(_key_bytes()), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode('utf-8')
