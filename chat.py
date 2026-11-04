"""Two-way terminal chat using RSA session exchange and AES-GCM."""
import argparse
import json
from pathlib import Path
import socket
import sys
import threading

from chat_protocol import (FrameReader, ProtocolError,
                           RecordReceiver, create_session, encode_frame,
                           encrypt_record, recover_master, validate_header,
                           validate_name)
from rsa_modes import generate_key, validate_private, validate_public

DEFAULT_KEY_FILE = Path(__file__).with_name('chat_private_key.json')


def setup_key(path, bits=6):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # This is the legitimate receiver's educational private key. The passive
    # attacker never reads this file and reconstructs d from measured factors.
    key = generate_key(bits)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(key, stream, indent=2)
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
    try:
        validate_private(key)
    except ValueError as error:
        raise ProtocolError('Invalid receiver RSA key file') from error
    return key


def _required(reader):
    frame = reader.read()
    if frame is None:
        raise ProtocolError('Peer disconnected during handshake')
    return frame


def client_handshake(connection, reader, name):
    validate_name(name)
    greeting = _required(reader)
    try:
        version = validate_public(greeting.get('N'), greeting.get('e'))
    except ValueError as error:
        raise ProtocolError('Unsupported server RSA key') from error
    expected = {'type': 'public_key', 'protocol': 'ACG-CHAT', 'version': version,
                'N': greeting['N'], 'e': greeting['e']}
    if set(greeting) != set(expected) | {'name'}:
        raise ProtocolError('Invalid server public-key greeting')
    for field, value in expected.items():
        if type(greeting[field]) is not type(value) or greeting[field] != value:
            raise ProtocolError('Unsupported server public-key greeting')
    validate_name(greeting['name'])
    header, master = create_session(name, greeting['name'], public_key=(greeting['N'], greeting['e']))
    connection.sendall(encode_frame({'type': 'session', 'header': header}))
    ready = _required(reader)
    if ready != {'type': 'ready', 'session_id': header['session_id']}:
        raise ProtocolError('Invalid server ready response')
    return header, master


def server_handshake(connection, reader, name, private_exponent, *, public_key=(33, 3)):
    validate_name(name)
    modulus, exponent = public_key
    version = validate_public(modulus, exponent)
    greeting = {'protocol': 'ACG-CHAT', 'version': version, 'N': modulus, 'e': exponent}
    connection.sendall(encode_frame({'type': 'public_key', **greeting, 'name': name}))
    frame = _required(reader)
    if set(frame) != {'type', 'header'} or frame['type'] != 'session':
        raise ProtocolError('Invalid session handshake')
    header = validate_header(frame['header'])
    if (header['N'], header['e']) != public_key:
        raise ProtocolError('Session RSA key does not match the server key')
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


def run_interactive_chat(connection, reader, header, master, role):
    from terminal_ui import TerminalChatUI
    outgoing, incoming = ('a_to_b', 'b_to_a') if role == 'alice' else ('b_to_a', 'a_to_b')
    own_name = header[role]
    peer_name = header['bob' if role == 'alice' else 'alice']
    receiver = RecordReceiver(header, master, incoming)
    stopped = threading.Event()
    sequence = 0

    def send(text):
        nonlocal sequence
        if stopped.is_set():
            ui.notice('Disconnected. /quit to close.')
            return False
        try:
            frame = encrypt_record(header, master, outgoing, sequence, text)
            connection.sendall(encode_frame(frame))
        except ProtocolError as error:
            ui.notice(str(error))
            return False
        except OSError:
            stopped.set()
            _shutdown(connection)
            ui.set_disconnected()
            return False
        sequence += 1
        return True

    def quit_chat():
        stopped.set()
        _shutdown(connection)

    rsa_label = 'RSA-33' if header['N'] == 33 else f'RSA-{header["N"].bit_length()}'
    ui = TerminalChatUI(own_name, peer_name, header['session_id'], send, quit_chat,
                        rsa_label=rsa_label)

    def receive():
        try:
            while not stopped.is_set():
                frame = reader.read()
                if frame is None:
                    break
                ui.message(peer_name, receiver.accept(frame))
        except (OSError, ProtocolError) as error:
            if not stopped.is_set():
                ui.notice(str(error))
        finally:
            was_stopped = stopped.is_set()
            stopped.set()
            _shutdown(connection)
            if not was_stopped:
                ui.set_disconnected()

    network_thread = threading.Thread(target=receive, name='chat-receiver', daemon=True)
    network_thread.start()
    try:
        ui.run()
    finally:
        quit_chat()
        network_thread.join(timeout=2)


def run_chat(connection, reader, header, master, role, plain=False):
    if not plain and sys.stdin.isatty() and sys.stdout.isatty():
        return run_interactive_chat(connection, reader, header, master, role)
    outgoing, incoming = ('a_to_b', 'b_to_a') if role == 'alice' else ('b_to_a', 'a_to_b')
    own_name = header[role]
    peer_name = header['bob' if role == 'alice' else 'alice']
    receiver = RecordReceiver(header, master, incoming)
    stopped = threading.Event()
    print(f'Connected session {header["session_id"]}: {own_name} <-> {peer_name}', flush=True)
    print('Enter to send | /quit to exit', flush=True)

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


def connect(host, port, name, plain=False):
    with socket.create_connection((host, port), timeout=10) as connection:
        reader = FrameReader(connection)
        try:
            header, master = client_handshake(connection, reader, name)
            connection.settimeout(None)
            run_chat(connection, reader, header, master, 'alice', plain=plain)
        finally:
            reader.close()


def listen(host, port, name, key_file, plain=False):
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
                header, master = server_handshake(connection, reader, name, key['d'],
                                                   public_key=(key['N'], key['e']))
                connection.settimeout(None)
                run_chat(connection, reader, header, master, 'bob', plain=plain)
            finally:
                reader.close()


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('setup', help='Create the receiver key file')
    setup.add_argument('--key-file', type=Path, default=DEFAULT_KEY_FILE)
    setup.add_argument('--bits', type=int, choices=(6, 248), default=6,
                       help='RSA modulus size: 6 for RSA-33, or 248')
    for command, name in (('listen', 'Bob'), ('connect', 'Alice')):
        peer = commands.add_parser(command)
        peer.add_argument('--host', default='127.0.0.1')
        peer.add_argument('--port', type=int, default=9001)
        peer.add_argument('--name', default=name)
        peer.add_argument('--plain', action='store_true', help='Use scrolling text instead of the full-screen chat')
        if command == 'listen':
            peer.add_argument('--key-file', type=Path, default=DEFAULT_KEY_FILE)
    args = parser.parse_args(argv)
    try:
        if args.command == 'setup':
            setup_key(args.key_file, bits=args.bits)
        elif not 1 <= args.port <= 65535:
            raise ProtocolError('Port must be in 1..65535')
        elif args.command == 'listen':
            listen(args.host, args.port, args.name, args.key_file, plain=args.plain)
        else:
            connect(args.host, args.port, args.name, plain=args.plain)
    except KeyboardInterrupt:
        print('\nExiting.', flush=True)
        return 0
    except (ValueError, OSError) as error:
        print(f'Error: {error}', file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
