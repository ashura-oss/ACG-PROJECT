"""Strict public package schema and deterministic authenticated header."""
import json
import re
from pathlib import Path

MAX_MESSAGE_BYTES = 4096
DEFAULT_PACKAGE = Path(__file__).with_name('encrypted_package.json')
HEADER_CONSTANTS = {'version': 1, 'aes_algorithm': 'AES-256-GCM',
                    'rsa_algorithm': 'TOY-RSA', 'key_encoding': 'BASE33-PAIRS-32-BYTES',
                    'N': 33, 'e': 3}


class PackageError(ValueError):
    pass


def header_bytes(header):
    return json.dumps(header, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def validate_package(package):
    if type(package) is not dict or set(package) != {'header', 'nonce_hex', 'ciphertext_and_tag_hex'}:
        raise PackageError('Invalid package fields')
    header = package['header']
    if type(header) is not dict or set(header) != set(HEADER_CONSTANTS) | {'wrapped_key_digits'}:
        raise PackageError('Invalid header fields')
    for field, expected in HEADER_CONSTANTS.items():
        if type(header[field]) is not type(expected) or header[field] != expected:
            raise PackageError(f'Unsupported or invalid {field}')
    digits = header['wrapped_key_digits']
    if type(digits) is not list or len(digits) != 64 or any(type(x) is not int or not 0 <= x < 33 for x in digits):
        raise PackageError('Wrapped key must contain 64 integers in 0..32')
    for field, minimum, maximum in [('nonce_hex', 12, 12),
                                     ('ciphertext_and_tag_hex', 16, MAX_MESSAGE_BYTES+16)]:
        value = package[field]
        if (type(value) is not str or len(value) % 2 or
                not minimum*2 <= len(value) <= maximum*2 or
                re.fullmatch('[0-9a-f]+', value) is None):
            raise PackageError(f'Invalid {field}')
    return package


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageError(f'Duplicate JSON key: {key}')
        result[key] = value
    return result


def load_package(path=DEFAULT_PACKAGE):
    try:
        # The schema fits well below this bound, even with indented JSON.
        with Path(path).open('r', encoding='utf-8') as stream:
            text = stream.read(65537)
        if len(text) > 65536:
            raise PackageError('Package exceeds size limit')
        return validate_package(json.loads(text, object_pairs_hook=_unique_object))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PackageError(f'Cannot load package: {error}') from error


def save_package(package, path=DEFAULT_PACKAGE, overwrite=False):
    validate_package(package)
    # Exclusive creation prevents an unconfirmed first-time overwrite.
    with Path(path).open('w' if overwrite else 'x', encoding='utf-8') as stream:
        json.dump(package, stream, indent=2)
        stream.write('\n')
