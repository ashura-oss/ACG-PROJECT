"""Two terminal peers communicating directly over educational RSA-33/AES-GCM."""
import argparse
import json
from pathlib import Path
import socket
import sys
import threading

from chat_protocol import (FrameReader, HEADER_CONSTANTS, ProtocolError,
                           RecordReceiver, create_session, encode_frame,
                           encrypt_record, recover_master, validate_header,
                           validate_name)

DEFAULT_KEY_FILE = Path(__file__).with_name('chat_private_key.json')


def setup_key(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # This is the legitimate receiver's educational private key. The passive
    # attacker never reads this file and reconstructs d from measured factors.
    with path.open('x', encoding='utf-8') as stream:
        json.dump({'N': 33, 'e': 3, 'd': 7}, stream, indent=2)
        stream.write('\n')
    try:
        path.chmod(0o600)
    except OSError:
        pass  # Windows ACLs, rather than POSIX modes, control file access.
    print(f'Created receiver key file: {path}', flush=True)


def load_key(path):
    try:
        with Path(path).open('r', encoding='utf-8') as stream:
            text = stream.read(1025)
        if len(text) > 1024:
            raise ValueError('Oversized key file')
        key = json.loads(text)
    except (OSError, ValueError) as error:
        raise ProtocolError(f'Cannot load receiver key; run chat.py setup first: {error}') from error
    if (type(key) is not dict or set(key) != {'N', 'e', 'd'} or
            any(type(key[field]) is not int for field in key) or
            key['N'] != 33 or key['e'] != 3 or not 1 <= key['d'] < 33 or
            any(pow(pow(digit, 3, 33), key['d'], 33) != digit for digit in range(33))):
        raise ProtocolError('Invalid RSA-33 receiver key file')
    return key


def _required(reader):
    frame = reader.read()
    if frame is None:
        raise ProtocolError('Peer disconnected during handshake')
    return frame


def client_handshake(connection, reader, name):
    validate_name(name)
    greeting = _required(reader)
    expected = {'type': 'public_key', 'protocol': 'ACG-CHAT', 'version': 1, 'N': 33, 'e': 3}
    if set(greeting) != set(expected) | {'name'}:
        raise ProtocolError('Invalid server public-key greeting')
    for field, value in expected.items():
        if type(greeting[field]) is not type(value) or greeting[field] != value:
            raise ProtocolError('Unsupported server public-key greeting')
    validate_name(greeting['name'])
    header, master = create_session(name, greeting['name'])
    connection.sendall(encode_frame({'type': 'session', 'header': header}))
    ready = _required(reader)
    if ready != {'type': 'ready', 'session_id': header['session_id']}:
        raise ProtocolError('Invalid server ready response')
    return header, master


def server_handshake(connection, reader, name, private_exponent):
    validate_name(name)
    greeting = {field: HEADER_CONSTANTS[field] for field in ('protocol', 'version', 'N', 'e')}
    connection.sendall(encode_frame({'type': 'public_key', **greeting, 'name': name}))
    frame = _required(reader)
    if set(frame) != {'type', 'header'} or frame['type'] != 'session':
        raise ProtocolError('Invalid session handshake')
    header = validate_header(frame['header'])
    if header['bob'] != name:
        raise ProtocolError('Session receiver label does not match the greeting')
    master = recover_master(header, private_exponent)
    connection.sendall(encode_frame({'type': 'ready', 'session_id': header['session_id']}))
    return header, master


def _shutdown(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def run_chat(connection, reader, header, master, role):
    outgoing, incoming = ('a_to_b', 'b_to_a') if role == 'alice' else ('b_to_a', 'a_to_b')
    own_name = header[role]
    peer_name = header['bob' if role == 'alice' else 'alice']
    receiver = RecordReceiver(header, master, incoming)
    stopped = threading.Event()
    print(f'Connected session {header["session_id"]}: {own_name} <-> {peer_name}', flush=True)
    print('RSA-33 teaching protocol; names are labels, not authenticated identities.', flush=True)
    print('Type a message and press Enter. /quit exits. Maximum 4096 UTF-8 bytes.', flush=True)

    def send_input():
        sequence = 0
        while not stopped.is_set():
            try:
                text = input('> ' if sys.stdin.isatty() else '')
            except (EOFError, OSError):
                break
            if stopped.is_set() or text == '/quit':
                break
            try:
                frame = encrypt_record(header, master, outgoing, sequence, text)
            except ProtocolError as error:
                print(f'Input error: {error}', flush=True)
                continue
            try:
                connection.sendall(encode_frame(frame))
            except OSError:
                break
            sequence += 1
            print(f'[You -> {peer_name}] {text}', flush=True)
        stopped.set()
        _shutdown(connection)

    threading.Thread(target=send_input, name='chat-input', daemon=True).start()
    try:
        while not stopped.is_set():
            frame = reader.read()
            if frame is None:
                break
            text = receiver.accept(frame)
            print(f'[{peer_name} -> You] {text}', flush=True)
    except OSError:
        if not stopped.is_set():
            raise
    finally:
        stopped.set()
        _shutdown(connection)
        print('Chat disconnected.', flush=True)


def connect(host, port, name):
    with socket.create_connection((host, port), timeout=10) as connection:
        reader = FrameReader(connection)
        try:
            header, master = client_handshake(connection, reader, name)
            connection.settimeout(None)
            run_chat(connection, reader, header, master, 'alice')
        finally:
            reader.close()


def listen(host, port, name, key_file):
    key = load_key(key_file)
    validate_name(name)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        print(f'Listening on {host}:{listener.getsockname()[1]} as {name}', flush=True)
        with listener.accept()[0] as connection:
            connection.settimeout(10)
            reader = FrameReader(connection)
            try:
                header, master = server_handshake(connection, reader, name, key['d'])
                connection.settimeout(None)
                run_chat(connection, reader, header, master, 'bob')
            finally:
                reader.close()


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('setup', help='Create the legitimate receiver key file once')
    setup.add_argument('--key-file', type=Path, default=DEFAULT_KEY_FILE)
    for command, name in (('listen', 'Bob'), ('connect', 'Alice')):
        peer = commands.add_parser(command)
        peer.add_argument('--host', default='127.0.0.1')
        peer.add_argument('--port', type=int, default=9001)
        peer.add_argument('--name', default=name)
        if command == 'listen':
            peer.add_argument('--key-file', type=Path, default=DEFAULT_KEY_FILE)
    args = parser.parse_args(argv)
    try:
        if args.command == 'setup':
            setup_key(args.key_file)
        elif not 1 <= args.port <= 65535:
            raise ProtocolError('Port must be in 1..65535')
        elif args.command == 'listen':
            listen(args.host, args.port, args.name, args.key_file)
        else:
            connect(args.host, args.port, args.name)
    except KeyboardInterrupt:
        print('\nExiting.', flush=True)
        return 0
    except (ValueError, OSError) as error:
        print(f'Error: {error}', file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
