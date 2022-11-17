from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

# keys
def write_key(pem, fpath):
    with open(fpath, 'wb') as f:
        f.write(pem)

def save_key_pair(private_key, priv_path):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    write_key(private_pem, priv_path)

def generate_key_pair():
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    public_key = private_key.public_key()
    return private_key, public_key

def get_key_pair(KEYS_DIR=None, KEY_FILE=None):
    private_key, public_key = generate_key_pair()

    # must save cert key to file
    if KEYS_DIR is not None and KEY_FILE is not None:
        priv_path = KEYS_DIR + KEY_FILE
        if not os.path.exists(KEYS_DIR):
            os.makedirs(KEYS_DIR)
        save_key_pair(private_key, priv_path)

    return private_key, public_key

# encapsulate crypto lib utils
def sign(private_key, message):
    signature = private_key.sign(
        message.encode("utf8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# https://www.rfc-editor.org/rfc/rfc7638 [p3]
# https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
def get_thumbprint(bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes)
    return digest.finalize()