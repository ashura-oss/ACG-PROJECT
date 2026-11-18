"""RSA session establishment and authenticated chat records.

The transport is framed TCP, not TLS. RSA-2048 uses OAEP-SHA256; the optional
RSA-33 and RSA-248 profiles are educational weak-key modes. Names
are display labels, not authenticated identities. Both directions have their
own derived AES key and monotonically increasing nonce counter.
"""
import json
import re
import secrets
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from toy_rsa import unwrap_key, wrap_key
from rsa_modes import validate_public, private_key_object, public_key_object

MAX_FRAME_BYTES = 16384
MAX_MESSAGE_BYTES = 4096
DIRECTIONS = ('a_to_b', 'b_to_a')
HEADER_CONSTANTS = {'protocol': 'ACG-CHAT', 'version': 1, 'N': 33, 'e': 3,
                    'aes_algorithm': 'AES-256-GCM', 'kdf': 'HKDF-SHA256'}
_HEADER_FIELDS = set(HEADER_CONSTANTS) | {'session_id', 'alice', 'bob', 'wrapped_key_digits'}
_HEADER_V2_CONSTANTS = {**HEADER_CONSTANTS, 'version': 2, 'e': 65537,
                        'key_encoding': 'RSA-SEED-128'}
_HEADER_V2_FIELDS = set(_HEADER_V2_CONSTANTS) | {'session_id', 'alice', 'bob', 'wrapped_seed_hex'}
_HEADER_V3_CONSTANTS = {**HEADER_CONSTANTS, 'version': 3, 'e': 65537,
                        'key_encoding': 'RSA-OAEP-SHA256'}
_HEADER_V3_FIELDS = set(_HEADER_V3_CONSTANTS) | {'session_id', 'alice', 'bob', 'wrapped_key_hex'}
HYBRID_KEM = 'X25519MLKEM768'
_HEADER_V4_CONSTANTS = {'protocol': 'ACG-CHAT', 'version': 4, 'aes_algorithm': 'AES-256-GCM',
                        'kdf': 'HKDF-SHA256', 'key_encoding': HYBRID_KEM}
_HEADER_V4_FIELDS = set(_HEADER_V4_CONSTANTS) | {'session_id', 'alice', 'bob', 'x25519_ephemeral_hex',
                                                 'mlkem_ciphertext_hex', 'receiver_key_sha256'}
_RECORD_FIELDS = {'type', 'session_id', 'direction', 'sequence', 'ciphertext_and_tag_hex'}


TOY_RSA_ENCODING = 'TOY-RSA-BASE-N'
TOY_RSA_BITS = (7, 8)
_HEADER_V5_CONSTANTS = {'protocol': 'ACG-CHAT', 'version': 5, 'aes_algorithm': 'AES-256-GCM',
                        'kdf': 'HKDF-SHA256', 'key_encoding': TOY_RSA_ENCODING}
_HEADER_V5_FIELDS = set(_HEADER_V5_CONSTANTS) | {'N', 'e', 'session_id', 'alice', 'bob',
                                                 'wrapped_key_digits'}


def is_toy_rsa(header):
    """True for the small, Shor-crackable RSA profile used by the desktop apps."""
    return type(header) is dict and header.get('version') == 5


def toy_digit_count(modulus):
    """How many base-N digits a 256-bit AES key needs."""
    count, value = 0, (1 << 256) - 1
    while value:
        value //= modulus
        count += 1
    return count


def validate_toy_public(modulus, exponent):
    if type(modulus) is not int or type(exponent) is not int:
        raise ProtocolError('RSA parameters must be integers')
    if modulus.bit_length() not in TOY_RSA_BITS or modulus % 2 == 0:
        raise ProtocolError('Toy RSA modulus must be an odd 7 or 8-bit number')
    if not 3 <= exponent < modulus:
        raise ProtocolError('Invalid toy RSA public exponent')
    return modulus, exponent


def create_toy_session(alice, bob, public_key):
    """Lock a fresh AES-256 key with small RSA, one base-N digit at a time."""
    validate_name(alice)
    validate_name(bob)
    modulus, exponent = validate_toy_public(*public_key)
    master = AESGCM.generate_key(bit_length=256)
    value, digits = int.from_bytes(master, 'big'), []
    for _ in range(toy_digit_count(modulus)):
        value, digit = divmod(value, modulus)
        digits.append(digit)
    header = {**_HEADER_V5_CONSTANTS, 'N': modulus, 'e': exponent, 'session_id': uuid.uuid4().hex,
              'alice': alice, 'bob': bob,
              'wrapped_key_digits': [pow(digit, exponent, modulus) for digit in reversed(digits)]}
    return validate_header(header), master


def _recover_toy_master(header, private_exponent):
    modulus = header['N']
    value = 0
    for wrapped in header['wrapped_key_digits']:
        value = value * modulus + pow(wrapped, private_exponent, modulus)
    if value >= 1 << 256:
        raise ProtocolError('Recovered digits do not form an AES-256 key')
    return value.to_bytes(32, 'big')


def is_hybrid(header):
    """True for the post-quantum hybrid profile, which has no RSA modulus."""
    return type(header) is dict and header.get('version') == 4


def _hex(value, length, what):
    if type(value) is not str or re.fullmatch('[0-9a-f]{%d}' % (2 * length), value) is None:
        raise ProtocolError(f'Invalid {what}')
    return bytes.fromhex(value)


class ProtocolError(ValueError):
    """Malformed, unsupported, or out-of-sequence chat data."""


class AuthenticationFailure(ProtocolError):
    """No unauthenticated plaintext is returned on this exception."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError('Duplicate JSON key')
        result[key] = value
    return result


def decode_frame(line):
    if type(line) is not bytes or not line.endswith(b'\n'):
        raise ProtocolError('Incomplete frame: expected a newline terminator')
    if len(line) > MAX_FRAME_BYTES:
        raise ProtocolError('Frame exceeds size limit')
    try:
        value = json.loads(line.decode('ascii'), object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError('Invalid JSON constant')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProtocolError('Invalid JSON frame') from error
    if type(value) is not dict:
        raise ProtocolError('Frame must be a JSON object')
    return value


def encode_frame(frame):
    if type(frame) is not dict:
        raise ProtocolError('Frame must be a JSON object')
    try:
        line = canonical(frame) + b'\n'
    except (ValueError, TypeError, RecursionError) as error:
        raise ProtocolError('Invalid JSON frame') from error
    if len(line) > MAX_FRAME_BYTES:
        raise ProtocolError('Frame exceeds size limit')
    return line


def validate_name(name):
    if type(name) is not str or not 1 <= len(name) <= 32 or not name.isprintable():
        raise ProtocolError('Name must contain 1 to 32 printable characters')
    try:
        name.encode('utf-8')
    except UnicodeError as error:
        raise ProtocolError('Name must be valid UTF-8') from error
    return name


def _session_id(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{32}', value) is None:
        raise ProtocolError('Invalid session identifier')


def validate_header(header):
    if type(header) is not dict or type(header.get('version')) is not int:
        raise ProtocolError('Invalid session header fields')
    version = header['version']
    if version == 5:
        if set(header) != _HEADER_V5_FIELDS:
            raise ProtocolError('Invalid session header fields')
        for field, expected in _HEADER_V5_CONSTANTS.items():
            if type(header[field]) is not type(expected) or header[field] != expected:
                raise ProtocolError(f'Unsupported session parameter: {field}')
        modulus, _ = validate_toy_public(header['N'], header['e'])
        _session_id(header['session_id'])
        validate_name(header['alice'])
        validate_name(header['bob'])
        digits = header['wrapped_key_digits']
        if (type(digits) is not list or len(digits) != toy_digit_count(modulus) or
                any(type(value) is not int or not 0 <= value < modulus for value in digits)):
            raise ProtocolError('Invalid wrapped key digits')
        return header
    if version == 4:
        if set(header) != _HEADER_V4_FIELDS:
            raise ProtocolError('Invalid session header fields')
        for field, expected in _HEADER_V4_CONSTANTS.items():
            if type(header[field]) is not type(expected) or header[field] != expected:
                raise ProtocolError(f'Unsupported session parameter: {field}')
        _session_id(header['session_id'])
        validate_name(header['alice'])
        validate_name(header['bob'])
        _hex(header['x25519_ephemeral_hex'], 32, 'X25519 ephemeral key')
        _hex(header['mlkem_ciphertext_hex'], 1088, 'ML-KEM-768 ciphertext')
        _hex(header['receiver_key_sha256'], 32, 'receiver key fingerprint')
        return header
    profiles = {1: (_HEADER_FIELDS, HEADER_CONSTANTS),
                2: (_HEADER_V2_FIELDS, _HEADER_V2_CONSTANTS),
                3: (_HEADER_V3_FIELDS, _HEADER_V3_CONSTANTS)}
    if version not in profiles:
        raise ProtocolError('Invalid session header fields')
    fields, constants = profiles[version]
    if set(header) != fields:
        raise ProtocolError('Invalid session header fields')
    for field, expected in constants.items():
        if field == 'N' and version in (2, 3):
            continue
        if type(header[field]) is not type(expected) or header[field] != expected:
            raise ProtocolError(f'Unsupported session parameter: {field}')
    try:
        if validate_public(header['N'], header['e']) != version:
            raise ValueError('RSA profile does not match the session version')
    except ValueError as error:
        raise ProtocolError(str(error)) from error
    _session_id(header['session_id'])
    validate_name(header['alice'])
    validate_name(header['bob'])
    if version == 1:
        digits = header['wrapped_key_digits']
        if (type(digits) is not list or len(digits) != 64 or
                any(type(value) is not int or not 0 <= value < 33 for value in digits)):
            raise ProtocolError('Wrapped key must contain 64 integers in 0..32')
    elif version == 2:
        wrapped = header['wrapped_seed_hex']
        if (type(wrapped) is not str or re.fullmatch('[0-9a-f]{62}', wrapped) is None or
                int(wrapped, 16) >= header['N']):
            raise ProtocolError('Invalid wrapped session seed')
    else:
        wrapped = header['wrapped_key_hex']
        if (type(wrapped) is not str or re.fullmatch('[0-9a-f]{512}', wrapped) is None or
                int(wrapped, 16) >= header['N']):
            raise ProtocolError('Invalid wrapped session key')
    return header


def _seed_master(seed, session_id):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(session_id),
                info=b'ACG-CHAT-v2/master').derive(seed)


def _oaep_label(header):
    return canonical({field: value for field, value in header.items() if field != 'wrapped_key_hex'})


def create_session(alice, bob, *, public_key=(33, 3)):
    validate_name(alice)
    validate_name(bob)
    try:
        modulus, exponent = public_key
        version = validate_public(modulus, exponent)
    except (ValueError, TypeError) as error:
        raise ProtocolError('Invalid RSA public key') from error
    if version == 3:
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256
        master = AESGCM.generate_key(bit_length=256)
        header = {**_HEADER_V3_CONSTANTS, 'N': modulus, 'session_id': uuid.uuid4().hex,
                  'alice': alice, 'bob': bob}
        cipher = PKCS1_OAEP.new(public_key_object(modulus, exponent), hashAlgo=SHA256,
                               label=_oaep_label(header))
        header['wrapped_key_hex'] = cipher.encrypt(master).hex()
        return validate_header(header), master
    if version == 2:
        session_id = uuid.uuid4().hex
        seed = secrets.token_bytes(16)
        wrapped = pow(int.from_bytes(seed, 'big'), exponent, modulus)
        header = {**_HEADER_V2_CONSTANTS, 'N': modulus, 'session_id': session_id,
                  'alice': alice, 'bob': bob, 'wrapped_seed_hex': wrapped.to_bytes(31, 'big').hex()}
        return validate_header(header), _seed_master(seed, session_id)
    master = AESGCM.generate_key(bit_length=256)
    header = {**HEADER_CONSTANTS, 'session_id': uuid.uuid4().hex,
              'alice': alice, 'bob': bob, 'wrapped_key_digits': wrap_key(master)}
    return validate_header(header), master


def generate_hybrid_key():
    """Receiver key file for the hybrid profile: X25519 plus ML-KEM-768."""
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
    return {'kem': HYBRID_KEM,
            'x25519_private_hex': x25519.X25519PrivateKey.generate().private_bytes_raw().hex(),
            'mlkem_seed_hex': mlkem.MLKEM768PrivateKey.generate().private_bytes_raw().hex()}


def _hybrid_private(key):
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
    if type(key) is not dict or set(key) != {'kem', 'x25519_private_hex', 'mlkem_seed_hex'} or key['kem'] != HYBRID_KEM:
        raise ProtocolError('Invalid hybrid key fields')
    try:
        classical = x25519.X25519PrivateKey.from_private_bytes(_hex(key['x25519_private_hex'], 32, 'X25519 private key'))
        post_quantum = mlkem.MLKEM768PrivateKey.from_seed_bytes(_hex(key['mlkem_seed_hex'], 64, 'ML-KEM-768 seed'))
    except ValueError as error:
        raise ProtocolError('Invalid hybrid private key') from error
    return classical, post_quantum


def validate_hybrid_private(key):
    _hybrid_private(key)
    return key


def hybrid_public(key):
    """The two public keys the receiver announces in its greeting."""
    classical, post_quantum = _hybrid_private(key)
    return {'x25519_public_hex': classical.public_key().public_bytes_raw().hex(),
            'mlkem_public_hex': post_quantum.public_key().public_bytes_raw().hex()}


def _hybrid_fingerprint(public):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes.fromhex(public['x25519_public_hex']) + bytes.fromhex(public['mlkem_public_hex']))
    return digest.finalize().hex()


def _hybrid_master(post_quantum_secret, classical_secret, header):
    # Both secrets feed one KDF: an attacker must break ML-KEM and X25519.
    context = canonical(header)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(header['session_id']),
                info=b'ACG-CHAT-v4/master/' + context).derive(post_quantum_secret + classical_secret)


def create_hybrid_session(alice, bob, public):
    """Sender side: ephemeral X25519 plus ML-KEM-768 encapsulation."""
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
    validate_name(alice)
    validate_name(bob)
    if type(public) is not dict or set(public) != {'x25519_public_hex', 'mlkem_public_hex'}:
        raise ProtocolError('Invalid hybrid public key')
    try:
        classical_peer = x25519.X25519PublicKey.from_public_bytes(_hex(public['x25519_public_hex'], 32, 'X25519 public key'))
        post_quantum_peer = mlkem.MLKEM768PublicKey.from_public_bytes(_hex(public['mlkem_public_hex'], 1184, 'ML-KEM-768 public key'))
        ephemeral = x25519.X25519PrivateKey.generate()
        classical_secret = ephemeral.exchange(classical_peer)
        post_quantum_secret, ciphertext = post_quantum_peer.encapsulate()
    except ValueError as error:
        raise ProtocolError('Invalid hybrid public key') from error
    header = {**_HEADER_V4_CONSTANTS, 'session_id': uuid.uuid4().hex, 'alice': alice, 'bob': bob,
              'x25519_ephemeral_hex': ephemeral.public_key().public_bytes_raw().hex(),
              'mlkem_ciphertext_hex': bytes(ciphertext).hex(),
              'receiver_key_sha256': _hybrid_fingerprint(public)}
    return validate_header(header), _hybrid_master(bytes(post_quantum_secret), classical_secret, header)


def recover_hybrid_master(header, key):
    """Receiver side. Needs both private keys; there is no RSA modulus to factor."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    validate_header(header)
    if not is_hybrid(header):
        raise ProtocolError('Not a hybrid session')
    classical, post_quantum = _hybrid_private(key)
    if header['receiver_key_sha256'] != _hybrid_fingerprint(hybrid_public(key)):
        raise ProtocolError('Session was created for a different receiver key')
    try:
        classical_secret = classical.exchange(
            x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(header['x25519_ephemeral_hex'])))
        post_quantum_secret = post_quantum.decapsulate(bytes.fromhex(header['mlkem_ciphertext_hex']))
    except ValueError as error:
        raise ProtocolError('Hybrid key agreement failed') from error
    return _hybrid_master(bytes(post_quantum_secret), classical_secret, header)


def derive_keys(master, header):
    validate_header(header)
    if type(master) is not bytes or len(master) != 32:
        raise ProtocolError('Session secret must be 32 bytes')
    context = canonical(header)
    return {direction: HKDF(algorithm=hashes.SHA256(), length=32,
                            salt=bytes.fromhex(header['session_id']),
                            info=f'ACG-CHAT-v{header["version"]}/'.encode('ascii') + direction.encode('ascii') + b'/' + context).derive(master)
            for direction in DIRECTIONS}


def recover_master(header, private_exponent):
    validate_header(header)
    if is_hybrid(header):
        raise ProtocolError('Hybrid sessions have no RSA private exponent')
    if type(private_exponent) is not int or not 1 <= private_exponent < header['N']:
        raise ProtocolError('Invalid RSA private exponent')
    if is_toy_rsa(header):
        return _recover_toy_master(header, private_exponent)
    if header['version'] == 3:
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256
        try:
            key = private_key_object(header['N'], header['e'], private_exponent)
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256, label=_oaep_label(header))
            master = cipher.decrypt(bytes.fromhex(header['wrapped_key_hex']))
            if len(master) != 32:
                raise ValueError('Invalid session key length')
            return master
        except (ValueError, TypeError) as error:
            raise ProtocolError('RSA key unwrap failed') from error
    if header['version'] == 2:
        wrapped = int(header['wrapped_seed_hex'], 16)
        seed = pow(wrapped, private_exponent, header['N'])
        if seed >= 2**128 or pow(seed, header['e'], header['N']) != wrapped:
            raise ProtocolError('RSA private key does not recover a valid session seed')
        return _seed_master(seed.to_bytes(16, 'big'), header['session_id'])
    try:
        return unwrap_key(header['wrapped_key_digits'], private_exponent)
    except ValueError as error:
        raise ProtocolError('Recovered key digits do not represent a session secret') from error


def _record_metadata(header, direction, sequence):
    if type(direction) is not str or direction not in DIRECTIONS:
        raise ProtocolError('Invalid message direction')
    if type(sequence) is not int or not 0 <= sequence < 2**64:
        raise ProtocolError('Invalid message sequence')
    return {'type': 'message', 'session_id': header['session_id'],
            'direction': direction, 'sequence': sequence}


def _aad(header, metadata):
    return canonical({'header': header, **metadata})


def _message_bytes(text):
    if type(text) is not str or any(not character.isprintable() for character in text):
        raise ProtocolError('Enter a single line of printable text')
    try:
        message = text.encode('utf-8')
    except UnicodeError as error:
        raise ProtocolError('Message must be valid UTF-8') from error
    if len(message) > MAX_MESSAGE_BYTES:
        raise ProtocolError('Message exceeds 4096 UTF-8 bytes')
    return message


def encrypt_record(header, master, direction, sequence, text):
    validate_header(header)
    metadata = _record_metadata(header, direction, sequence)
    message = _message_bytes(text)
    key = derive_keys(master, header)[direction]
    ciphertext = AESGCM(key).encrypt(sequence.to_bytes(12, 'big'), message, _aad(header, metadata))
    return {**metadata, 'ciphertext_and_tag_hex': ciphertext.hex()}


def validate_record(frame, header=None):
    if type(frame) is not dict or set(frame) != _RECORD_FIELDS or frame['type'] != 'message':
        raise ProtocolError('Invalid encrypted message fields')
    _session_id(frame['session_id'])
    _record_metadata(frame, frame['direction'], frame['sequence'])
    ciphertext = frame['ciphertext_and_tag_hex']
    if (type(ciphertext) is not str or len(ciphertext) % 2 or
            not 32 <= len(ciphertext) <= 2 * (MAX_MESSAGE_BYTES + 16) or
            re.fullmatch('[0-9a-f]+', ciphertext) is None):
        raise ProtocolError('Invalid ciphertext length or encoding')
    if header is not None:
        validate_header(header)
        if frame['session_id'] != header['session_id']:
            raise ProtocolError('Message belongs to another session')
    return frame


def decrypt_record(header, master, frame):
    validate_record(frame, header)
    metadata = _record_metadata(header, frame['direction'], frame['sequence'])
    key = derive_keys(master, header)[frame['direction']]
    try:
        cleartext = AESGCM(key).decrypt(frame['sequence'].to_bytes(12, 'big'),
                                       bytes.fromhex(frame['ciphertext_and_tag_hex']),
                                       _aad(header, metadata))
    except InvalidTag as error:
        raise AuthenticationFailure('Message authentication failed') from error
    try:
        text = cleartext.decode('utf-8')
    except UnicodeError as error:
        raise ProtocolError('Authenticated content is not UTF-8') from error
    _message_bytes(text)
    return text


class RecordReceiver:
    """Endpoint replay/order enforcement, independent for each direction."""
    def __init__(self, header, master, direction):
        validate_header(header)
        _record_metadata(header, direction, 0)
        self.header = header
        self.master = master
        self.direction = direction
        self.next_sequence = 0

    def accept(self, frame):
        validate_record(frame, self.header)
        if frame['direction'] != self.direction:
            raise ProtocolError('Unexpected message direction')
        if frame['sequence'] != self.next_sequence:
            raise ProtocolError('Unexpected message sequence (replay or missing message)')
        text = decrypt_record(self.header, self.master, frame)
        self.next_sequence += 1
        return text


class FrameReader:
    def __init__(self, connection):
        self.stream = connection.makefile('rb')

    def read(self):
        line = self.stream.readline(MAX_FRAME_BYTES + 1)
        return decode_frame(line) if line else None

    def close(self):
        self.stream.close()
