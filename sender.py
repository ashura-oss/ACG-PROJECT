import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from package_io import HEADER_CONSTANTS, MAX_MESSAGE_BYTES, header_bytes, validate_package
from toy_rsa import wrap_key


def encrypt_message(plaintext):
    if '\n' in plaintext or '\r' in plaintext:
        raise ValueError('Enter a single-line message')
    message = plaintext.encode('utf-8')
    if len(message) > MAX_MESSAGE_BYTES:
        raise ValueError('Message exceeds 4096 UTF-8 bytes')
    key = AESGCM.generate_key(bit_length=256)
    header = {**HEADER_CONSTANTS, 'wrapped_key_digits': wrap_key(key)}
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, message, header_bytes(header))
    return validate_package({'header': header, 'nonce_hex': nonce.hex(),
                             'ciphertext_and_tag_hex': ciphertext.hex()})
