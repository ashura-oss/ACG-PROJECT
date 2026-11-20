"""Wire format and crypto for ACG Chat.

Every message is AES-256-GCM. The AES key is locked one of two ways:
  rsa - a small random RSA key (7-bit), small enough for Shor's to crack
  pqc - X25519 + ML-KEM-768 (post-quantum hybrid)
Frames are one JSON object per line over TCP.
"""
import json
import re
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_FRAME = 16384
MAX_TEXT = 4096
DIRECTIONS = ('a_to_b', 'b_to_a')
RSA_VERSION, PQC_VERSION = 5, 4


class ProtocolError(ValueError):
    pass


# ---------- frames ----------
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def encode_frame(frame):
    line = canonical(frame) + b'\n'
    if len(line) > MAX_FRAME:
        raise ProtocolError('Frame too large')
    return line


def decode_frame(line):
    if not line.endswith(b'\n') or len(line) > MAX_FRAME:
        raise ProtocolError('Bad frame')
    try:
        frame = json.loads(line)
    except ValueError as error:
        raise ProtocolError('Bad frame') from error
    if type(frame) is not dict:
        raise ProtocolError('Bad frame')
    return frame


class FrameReader:
    def __init__(self, connection):
        self.stream = connection.makefile('rb')

    def read(self):
        line = self.stream.readline(MAX_FRAME + 1)
        return decode_frame(line) if line else None

    def close(self):
        self.stream.close()


def validate_name(name):
    if type(name) is not str or not 1 <= len(name) <= 32 or not name.isprintable():
        raise ProtocolError('Name must be 1 to 32 printable characters')
    return name


def _hex(value, length):
    if type(value) is not str or re.fullmatch('[0-9a-f]{%d}' % (2 * length), value) is None:
        raise ProtocolError('Bad hex field')
    return bytes.fromhex(value)


# ---------- rsa lock (Shor-crackable) ----------
def digit_count(n):
    """Base-N digits needed for a 256-bit AES key."""
    count, value = 0, (1 << 256) - 1
    while value:
        value //= n
        count += 1
    return count


def create_rsa_session(alice, bob, n, e):
    """Lock a fresh AES key with RSA, one base-N digit at a time (N is tiny)."""
    key = AESGCM.generate_key(bit_length=256)
    value, digits = int.from_bytes(key, 'big'), []
    for _ in range(digit_count(n)):
        value, digit = divmod(value, n)
        digits.insert(0, digit)
    header = {'version': RSA_VERSION, 'session_id': uuid.uuid4().hex, 'alice': alice, 'bob': bob,
              'N': n, 'e': e, 'locked_key': [pow(d, e, n) for d in digits]}
    return validate_header(header), key


def unlock_rsa_key(header, d):
    n, value = header['N'], 0
    for block in header['locked_key']:
        value = value * n + pow(block, d, n)
    if value >= 1 << 256:
        raise ProtocolError('Wrong private key')
    return value.to_bytes(32, 'big')


# ---------- post-quantum lock ----------
def generate_pqc_key():
    return {'x25519': x25519.X25519PrivateKey.generate(), 'mlkem': mlkem.MLKEM768PrivateKey.generate()}


def pqc_public(key):
    return {'x25519': key['x25519'].public_key().public_bytes_raw().hex(),
            'mlkem': key['mlkem'].public_key().public_bytes_raw().hex()}


def _pqc_master(pq_secret, classic_secret, header):
    # Both secrets feed one KDF, so an attacker must break ML-KEM and X25519.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(header['session_id']),
                info=b'ACG-PQC/' + canonical(header)).derive(pq_secret + classic_secret)


def create_pqc_session(alice, bob, public):
    peer_x = x25519.X25519PublicKey.from_public_bytes(_hex(public['x25519'], 32))
    peer_k = mlkem.MLKEM768PublicKey.from_public_bytes(_hex(public['mlkem'], 1184))
    ephemeral = x25519.X25519PrivateKey.generate()
    pq_secret, ciphertext = peer_k.encapsulate()
    header = {'version': PQC_VERSION, 'session_id': uuid.uuid4().hex, 'alice': alice, 'bob': bob,
              'x25519': ephemeral.public_key().public_bytes_raw().hex(), 'mlkem': bytes(ciphertext).hex()}
    validate_header(header)
    return header, _pqc_master(bytes(pq_secret), ephemeral.exchange(peer_x), header)


def unlock_pqc_key(header, key):
    classic = key['x25519'].exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(header['x25519'])))
    pq_secret = key['mlkem'].decapsulate(bytes.fromhex(header['mlkem']))
    return _pqc_master(bytes(pq_secret), classic, header)


# ---------- session header ----------
def validate_header(header):
    if type(header) is not dict:
        raise ProtocolError('Bad session header')
    version = header.get('version')
    fields = {'version', 'session_id', 'alice', 'bob'}
    if version == RSA_VERSION:
        fields |= {'N', 'e', 'locked_key'}
    elif version == PQC_VERSION:
        fields |= {'x25519', 'mlkem'}
    if set(header) != fields or version not in (RSA_VERSION, PQC_VERSION):
        raise ProtocolError('Bad session header')
    _hex(header['session_id'], 16)
    validate_name(header['alice'])
    validate_name(header['bob'])
    if version == RSA_VERSION:
        n, e, blocks = header['N'], header['e'], header['locked_key']
        if type(n) is not int or n.bit_length() not in (7, 8) or n % 2 == 0 or type(e) is not int or not 3 <= e < n:
            raise ProtocolError('Bad RSA key')
        if type(blocks) is not list or len(blocks) != digit_count(n) or any(type(b) is not int or not 0 <= b < n for b in blocks):
            raise ProtocolError('Bad locked key')
    else:
        _hex(header['x25519'], 32)
        _hex(header['mlkem'], 1088)
    return header


# ---------- messages ----------
def _message_key(master, header, direction):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(header['session_id']),
                info=direction.encode() + b'/' + canonical(header)).derive(master)


def encrypt_message(header, master, direction, sequence, text):
    data = text.encode('utf-8')
    if not data or len(data) > MAX_TEXT:
        raise ProtocolError('Message must be 1 to 4096 bytes')
    meta = {'type': 'message', 'session_id': header['session_id'], 'direction': direction, 'sequence': sequence}
    cipher = AESGCM(_message_key(master, header, direction)).encrypt(sequence.to_bytes(12, 'big'), data, canonical(meta))
    return {**meta, 'ciphertext': cipher.hex()}


def decrypt_message(header, master, frame):
    if (type(frame) is not dict or set(frame) != {'type', 'session_id', 'direction', 'sequence', 'ciphertext'}
            or frame['session_id'] != header['session_id'] or frame['direction'] not in DIRECTIONS
            or type(frame['sequence']) is not int or not 0 <= frame['sequence'] < 2 ** 64):
        raise ProtocolError('Bad message')
    meta = {k: frame[k] for k in ('type', 'session_id', 'direction', 'sequence')}
    try:
        data = AESGCM(_message_key(master, header, frame['direction'])).decrypt(
            frame['sequence'].to_bytes(12, 'big'), bytes.fromhex(frame['ciphertext']), canonical(meta))
    except (InvalidTag, ValueError) as error:
        raise ProtocolError('Message failed authentication') from error
    return data.decode('utf-8')
