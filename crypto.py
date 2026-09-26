import os
import base64
import json

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32


def derive_key(master_password, salt):
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=KEY_SIZE,
        type=Type.ID
    )


def encrypt_data(data, master_password):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(master_password, salt)
    aes = AESGCM(key)

    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, None)

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(ciphertext).decode()
    }


def decrypt_data(encrypted, master_password):
    try:
        salt = base64.b64decode(encrypted["salt"])
        nonce = base64.b64decode(encrypted["nonce"])
        ciphertext = base64.b64decode(encrypted["data"])

        key = derive_key(master_password, salt)
        aes = AESGCM(key)

        plaintext = aes.decrypt(nonce, ciphertext, None)

        return json.loads(plaintext.decode("utf-8"))

    except Exception:
        raise ValueError("Incorrect master password or corrupted vault.")