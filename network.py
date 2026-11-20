"""Chatter networking: keys, discovery, handshake, sessions.

Each chatter listens on a TCP port in PORTS and drops a heartbeat file in a
shared folder, so every open chatter on this computer can find the others.
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

from protocol import (PQC_VERSION, RSA_VERSION, FrameReader, ProtocolError, create_pqc_session,
                      create_rsa_session, decrypt_message, encode_frame, encrypt_message,
                      generate_pqc_key, pqc_public, unlock_pqc_key, unlock_rsa_key,
                      validate_header, validate_name)

PORTS = range(47100, 47200)
FOLDER = Path(os.environ.get('LOCALAPPDATA') or tempfile.gettempdir()) / 'ACG-Chat'


def random_rsa_key(bits=7):
    """N = p * q with exactly `bits` bits; small enough for Shor's simulation."""
    primes = [p for p in range(3, 1 << bits) if all(p % k for k in range(2, int(p ** 0.5) + 1))]
    p, q = random.choice([(p, q) for p in primes for q in primes if p < q and (p * q).bit_length() == bits])
    phi = (p - 1) * (q - 1)
    e = random.choice([e for e in range(3, p * q, 2) if math.gcd(e, phi) == 1])
    return {'N': p * q, 'e': e, 'd': pow(e, -1, phi)}


class Me:
    def __init__(self, name, mode):
        self.name, self.mode, self.id = validate_name(name), mode, uuid.uuid4().hex
        self.key = random_rsa_key() if mode == 'rsa' else generate_pqc_key()


# ---------- discovery ----------
def announce(me, port):
    FOLDER.mkdir(parents=True, exist_ok=True)
    path = FOLDER / f'{me.id}.json'
    try:
        path.with_suffix('.tmp').write_text(json.dumps({'name': me.name, 'mode': me.mode, 'port': port, 'time': time.time()}))
        os.replace(path.with_suffix('.tmp'), path)
    except PermissionError:
        pass  # someone is reading it; the next heartbeat retries


def leave(me):
    (FOLDER / f'{me.id}.json').unlink(missing_ok=True)


def online(mode=None, exclude=None):
    peers = []
    for path in FOLDER.glob('*.json'):
        try:
            peer = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if time.time() - peer.get('time', 0) > 4:
            continue
        if path.stem != exclude and (mode is None or peer['mode'] == mode):
            peers.append(peer)
    return sorted(peers, key=lambda p: p['name'].lower())


# ---------- handshake ----------
def _read(reader):
    frame = reader.read()
    if frame is None:
        raise ProtocolError('Disconnected')
    return frame


def dial_handshake(conn, reader, me):
    hello = _read(reader)
    peer = validate_name(hello.get('name'))
    if me.mode == 'rsa' and hello.get('version') == RSA_VERSION:
        header, key = create_rsa_session(me.name, peer, hello['N'], hello['e'])
    elif me.mode == 'pqc' and hello.get('version') == PQC_VERSION:
        header, key = create_pqc_session(me.name, peer, hello['public'])
    else:
        raise ProtocolError(f'{peer} uses a different lock')
    conn.sendall(encode_frame({'type': 'session', 'header': header}))
    if _read(reader) != {'type': 'ready'}:
        raise ProtocolError('Handshake failed')
    return header, key


def answer_handshake(conn, reader, me):
    if me.mode == 'rsa':
        hello = {'version': RSA_VERSION, 'N': me.key['N'], 'e': me.key['e']}
    else:
        hello = {'version': PQC_VERSION, 'public': pqc_public(me.key)}
    conn.sendall(encode_frame({'type': 'hello', 'name': me.name, **hello}))
    frame = _read(reader)
    header = validate_header(frame.get('header'))
    if frame.get('type') != 'session' or header['bob'] != me.name:
        raise ProtocolError('Handshake failed')
    if me.mode == 'rsa' and header['version'] == RSA_VERSION and header['N'] == me.key['N']:
        key = unlock_rsa_key(header, me.key['d'])
    elif me.mode == 'pqc' and header['version'] == PQC_VERSION:
        key = unlock_pqc_key(header, me.key)
    else:
        raise ProtocolError('Different lock')
    conn.sendall(encode_frame({'type': 'ready'}))
    return header, key


# ---------- sessions ----------
class Chat:
    def __init__(self, conn, reader, header, key, i_dialled):
        self.conn, self.reader, self.header, self.key = conn, reader, header, key
        self.out, self.into = ('a_to_b', 'b_to_a') if i_dialled else ('b_to_a', 'a_to_b')
        self.peer = header['bob'] if i_dialled else header['alice']
        self.sent = self.received = 0
        self.lock = threading.Lock()

    def send(self, text):
        with self.lock:
            self.conn.sendall(encode_frame(encrypt_message(self.header, self.key, self.out, self.sent, text)))
            self.sent += 1

    def listen(self, on_text, on_end):
        try:
            while (frame := self.reader.read()) is not None:
                if frame.get('direction') != self.into or frame.get('sequence') != self.received:
                    raise ProtocolError('Out-of-order message')
                on_text(self, decrypt_message(self.header, self.key, frame))
                self.received += 1
        except (OSError, ProtocolError):
            pass
        self.close()
        on_end(self)

    def close(self):
        for close in (lambda: self.conn.shutdown(socket.SHUT_RDWR), self.reader.close, self.conn.close):
            try:
                close()
            except OSError:
                pass


class Node:
    """Listens for chats and dials out. Callbacks fire on background threads."""

    def __init__(self, me, on_chat, on_text, on_end):
        self.me, self.on_chat, self.on_text, self.on_end = me, on_chat, on_text, on_end
        for port in PORTS:
            self.server = socket.socket()
            try:
                self.server.bind(('127.0.0.1', port))
                break
            except OSError:
                self.server.close()
        else:
            raise OSError('No free chat port')
        self.port = port
        self.server.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._start, args=(conn, False), daemon=True).start()

    def dial(self, port):
        self._start(socket.create_connection(('127.0.0.1', port), timeout=10), True)

    def _start(self, conn, dialling):
        reader = FrameReader(conn)
        try:
            conn.settimeout(10)
            handshake = dial_handshake if dialling else answer_handshake
            header, key = handshake(conn, reader, self.me)
            conn.settimeout(None)
        except (OSError, ProtocolError, ValueError, KeyError):
            reader.close()
            conn.close()
            if dialling:
                raise
            return
        chat = Chat(conn, reader, header, key, dialling)
        self.on_chat(chat)
        threading.Thread(target=chat.listen, args=(self.on_text, self.on_end), daemon=True).start()

    def stop(self):
        self.server.close()
