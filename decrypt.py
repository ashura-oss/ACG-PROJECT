import re
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from package_io import header_bytes, validate_package


class AuthenticationFailure(ValueError):
    pass


def parse_key(text):
    text = text.strip()
    if re.fullmatch('[0-9a-fA-F]{64}', text) is None:
        raise ValueError('Enter exactly 64 hexadecimal characters with no internal spaces')
    return bytes.fromhex(text)


def decrypt_message(package, entered_key):
    validate_package(package)
    key = parse_key(entered_key)
    try:
        plaintext = AESGCM(key).decrypt(bytes.fromhex(package['nonce_hex']),
                                       bytes.fromhex(package['ciphertext_and_tag_hex']),
                                       header_bytes(package['header']))
    except InvalidTag as error:
        raise AuthenticationFailure('Decryption/authentication failed') from error
    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValueError('Authenticated content is not UTF-8') from error
