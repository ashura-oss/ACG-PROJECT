"""Networking for the desktop chatter app: keys, discovery, handshakes, sessions.

Every chatter listens on its own TCP port in CHAT_PORTS and announces itself in a
small per-user registry folder, so any number of instances on this computer find
each other. Chatters only see and accept peers that use the same lock mode.

Modes
  'rsa' - the AES-256 session key is locked with a fresh random 7-bit RSA key
          (small enough for the Interceptor's Shor simulation to factor live).
  'pqc' - the AES-256 session key comes from X25519 + ML-KEM-768.
Messages are AES-256-GCM in both modes (chat_protocol records).
"""
import json
import math
import os
from pathlib import Path
import random
import socket
import tempfile
import threading
import time
import uuid

from chat_protocol import (FrameReader, ProtocolError, RecordReceiver, create_hybrid_session,
                           create_toy_session, encode_frame, encrypt_record, generate_hybrid_key,
                           hybrid_public, is_hybrid, is_toy_rsa, recover_hybrid_master,
                           recover_master, validate_header, validate_name, validate_toy_public)

CHAT_PORTS = (47100, 47199)
MODES = ('rsa', 'pqc')
MODE_LABELS = {'rsa': 'RSA (7-bit, crackable)', 'pqc': 'Post-quantum (X25519 + ML-KEM-768)'}
REGISTRY = Path(os.environ.get('LOCALAPPDATA') or tempfile.gettempdir()) / 'ACG-Chat' / 'peers'
STALE_SECONDS = 4.0
TOY_BITS = 7


def _primes(limit):
    sieve = bytearray([1]) * limit
    sieve[0:2] = b'\x00\x00'
    for value in range(2, int(limit ** 0.5) + 1):
        if sieve[value]:
            sieve[value*value::value] = bytearray(len(sieve[value*value::value]))
    return [value for value in range(3, limit) if sieve[value]]


def generate_toy_rsa(bits=TOY_BITS, rng=None):
    """Random small RSA key: N = p*q with distinct odd primes and exactly `bits` bits."""
    rng = rng or random.SystemRandom()
    primes = _primes(1 << bits)
    pairs = [(p, q) for i, p in enumerate(primes) for q in primes[i+1:]
             if (p * q).bit_length() == bits]
    p, q = rng.choice(pairs)
    phi = (p - 1) * (q - 1)
    exponents = [e for e in range(3, p * q) if e % 2 and math.gcd(e, phi) == 1 and pow(e, -1, phi) != e]
    e = rng.choice(exponents)
    return {'N': p * q, 'e': e, 'd': pow(e, -1, phi)}


class Identity:
    """This chatter's name, mode and private key material."""

    def __init__(self, name, mode):
        validate_name(name)
        if mode not in MODES:
            raise ValueError('Unknown mode')
        self.name, self.mode = name, mode
        self.peer_id = uuid.uuid4().hex
        self.key = generate_toy_rsa() if mode == 'rsa' else generate_hybrid_key()

    def public_summary(self):
        if self.mode == 'rsa':
            return f"RSA public key  N = {self.key['N']},  e = {self.key['e']}"
        return 'X25519 + ML-KEM-768 public keys (1,216 bytes)'


class Registry:
    """File-based discovery: one heartbeat file per running chatter."""

    def __init__(self, folder=REGISTRY):
        self.folder = Path(folder)

    def announce(self, identity, port):
        self.folder.mkdir(parents=True, exist_ok=True)
        entry = {'peer_id': identity.peer_id, 'name': identity.name, 'mode': identity.mode,
                 'port': port, 'updated': time.time()}
        path = self.folder / f'{identity.peer_id}.json'
        temporary = path.with_suffix('.tmp')
        try:
            temporary.write_text(json.dumps(entry), encoding='utf-8')
            os.replace(temporary, path)
        except PermissionError:
            pass  # another chatter is reading the file right now; the next heartbeat retries

    def withdraw(self, identity):
        try:
            (self.folder / f'{identity.peer_id}.json').unlink()
        except OSError:
            pass

    def peers(self, mode=None, exclude=None):
        found, now = [], time.time()
        for path in self.folder.glob('*.json') if self.folder.exists() else []:
            try:
                entry = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                continue
            if type(entry) is not dict or now - entry.get('updated', 0) > STALE_SECONDS:
                if type(entry) is dict and now - entry.get('updated', 0) > 60:
                    try:
                        path.unlink()
                    except OSError:
                        pass
                continue
            if entry.get('peer_id') == exclude or (mode and entry.get('mode') != mode):
                continue
            found.append(entry)
        return sorted(found, key=lambda entry: entry['name'].lower())

    def name_taken(self, name):
        return any(entry['name'].lower() == name.lower() for entry in self.peers())


def _required(reader):
    frame = reader.read()
    if frame is None:
        raise ProtocolError('Peer disconnected during handshake')
    return frame


def _greeting(identity):
    if identity.mode == 'rsa':
        return {'type': 'public_key', 'protocol': 'ACG-CHAT', 'version': 5,
                'N': identity.key['N'], 'e': identity.key['e'], 'name': identity.name}
    return {'type': 'public_key', 'protocol': 'ACG-CHAT', 'version': 4, 'kem': 'X25519MLKEM768',
            **hybrid_public(identity.key), 'name': identity.name}


def client_handshake(connection, reader, identity):
    """Dialling side ('alice'): read the peer's public key and send the locked AES key."""
    greeting = _required(reader)
    if type(greeting) is not dict or greeting.get('type') != 'public_key':
        raise ProtocolError('Invalid public-key greeting')
    peer = validate_name(greeting.get('name'))
    if identity.mode == 'rsa':
        if set(greeting) != {'type', 'protocol', 'version', 'N', 'e', 'name'} or greeting['version'] != 5:
            raise ProtocolError(f'{peer} does not use the RSA mode')
        header, master = create_toy_session(identity.name, peer, validate_toy_public(greeting['N'], greeting['e']))
    else:
        if (set(greeting) != {'type', 'protocol', 'version', 'kem', 'x25519_public_hex', 'mlkem_public_hex', 'name'}
                or greeting['version'] != 4):
            raise ProtocolError(f'{peer} does not use the post-quantum mode')
        header, master = create_hybrid_session(identity.name, peer, {
            'x25519_public_hex': greeting['x25519_public_hex'], 'mlkem_public_hex': greeting['mlkem_public_hex']})
    connection.sendall(encode_frame({'type': 'session', 'header': header}))
    if _required(reader) != {'type': 'ready', 'session_id': header['session_id']}:
        raise ProtocolError('Invalid ready response')
    return header, master


def server_handshake(connection, reader, identity):
    """Listening side ('bob'): announce the public key, unlock the AES key."""
    connection.sendall(encode_frame(_greeting(identity)))
    frame = _required(reader)
    if type(frame) is not dict or set(frame) != {'type', 'header'} or frame['type'] != 'session':
        raise ProtocolError('Invalid session handshake')
    header = validate_header(frame['header'])
    if header['bob'] != identity.name:
        raise ProtocolError('Session was addressed to another chatter')
    if identity.mode == 'rsa':
        if not is_toy_rsa(header) or (header['N'], header['e']) != (identity.key['N'], identity.key['e']):
            raise ProtocolError('Session does not use this chatter\'s RSA key')
        master = recover_master(header, identity.key['d'])
    else:
        if not is_hybrid(header):
            raise ProtocolError('Session does not use the post-quantum key exchange')
        master = recover_hybrid_master(header, identity.key)
    connection.sendall(encode_frame({'type': 'ready', 'session_id': header['session_id']}))
    return header, master


class Session:
    """One live encrypted conversation with one peer."""

    def __init__(self, connection, reader, header, master, role):
        self.connection, self.reader = connection, reader
        self.header, self.master, self.role = header, master, role
        self.outgoing, incoming = ('a_to_b', 'b_to_a') if role == 'alice' else ('b_to_a', 'a_to_b')
        self.peer = header['bob'] if role == 'alice' else header['alice']
        self.receiver = RecordReceiver(header, master, incoming)
        self.sequence = 0
        self.lock = threading.Lock()
        self.closed = False

    def send(self, text):
        with self.lock:
            frame = encrypt_record(self.header, self.master, self.outgoing, self.sequence, text)
            self.connection.sendall(encode_frame(frame))
            self.sequence += 1

    def receive_forever(self, on_message, on_closed):
        try:
            while True:
                frame = self.reader.read()
                if frame is None:
                    break
                on_message(self, self.receiver.accept(frame))
        except (OSError, ProtocolError) as error:
            if not self.closed:
                on_closed(self, str(error))
                return
        finally:
            self.close()
        on_closed(self, None)

    def close(self):
        self.closed = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.reader.close()
        except OSError:
            pass
        self.connection.close()


class Node:
    """Listener plus dialler for one chatter. Callbacks run on background threads."""

    def __init__(self, identity, on_session, on_message, on_closed, on_error):
        self.identity = identity
        self.on_session, self.on_message = on_session, on_message
        self.on_closed, self.on_error = on_closed, on_error
        self.listener = self._bind()
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        threading.Thread(target=self._accept_loop, name='accept', daemon=True).start()

    @staticmethod
    def _bind():
        for port in range(CHAT_PORTS[0], CHAT_PORTS[1] + 1):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.bind(('127.0.0.1', port))
            except OSError:
                listener.close()
                continue
            listener.listen(8)
            return listener
        raise OSError('No free chat port; close some chatter windows')

    def _accept_loop(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        connection.settimeout(10)
        reader = FrameReader(connection)
        try:
            header, master = server_handshake(connection, reader, self.identity)
        except (OSError, ProtocolError, ValueError) as error:
            self.on_error(f'Rejected an incoming chat: {error}')
            reader.close()
            connection.close()
            return
        connection.settimeout(None)
        self._start(Session(connection, reader, header, master, 'bob'))

    def dial(self, port):
        """Open a chat with the peer on `port` (blocking; run off the UI thread)."""
        connection = socket.create_connection(('127.0.0.1', port), timeout=10)
        reader = FrameReader(connection)
        try:
            header, master = client_handshake(connection, reader, self.identity)
        except BaseException:
            reader.close()
            connection.close()
            raise
        connection.settimeout(None)
        return self._start(Session(connection, reader, header, master, 'alice'))

    def _start(self, session):
        self.on_session(session)
        threading.Thread(target=session.receive_forever, args=(self.on_message, self.on_closed),
                         daemon=True).start()
        return session

    def stop(self):
        self.stopped.set()
        self.listener.close()
