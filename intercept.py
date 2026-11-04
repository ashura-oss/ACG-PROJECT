"""Recover chat sessions from passive captures using measured Shor results.

This program reads only public wire frames. It never opens an endpoint key
file. A capture process can keep collecting packets while Shor runs.
"""
import argparse
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import subprocess
import sys
import threading
import time

from chat_protocol import (DIRECTIONS, decrypt_record, recover_master,
                           validate_header, validate_record)
from shor import AttackFailure, run_factorization

MAX_CAPTURE_LINE = 131072


class CaptureError(ValueError):
    """A capture cannot safely be read or associated with a session."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CaptureError('Duplicate JSON key')
        result[key] = value
    return result


def _display(text):
    # File paths and externally supplied error strings must not inject terminal
    # control sequences. Authenticated chat text is validated by the protocol.
    return ''.join(char if char.isprintable() else repr(char)[1:-1]
                   for char in str(text))


@dataclass
class CapturedMessage:
    session_id: str
    connection_id: str
    frame: dict
    time_ns: int
    ordinal: int
    processed: bool = False
    error: str | None = None


@dataclass
class CapturedSession:
    header: dict
    connection_id: str
    master: bytes | None = None
    records: list = field(default_factory=list)
    next_sequence: dict = field(default_factory=lambda: dict.fromkeys(DIRECTIONS, 0))
    error_count: int = 0
    decrypted_count: int = 0


class CaptureQueue:
    """Incrementally read a public capture, recover keys, and authenticate it.

    A complete session handshake must precede its records. Sequence gaps and
    replayed records are explicit errors, never a successfully complete chat.
    Only complete JSONL lines are consumed while a live writer is appending.
    """

    def __init__(self, capture_path, seed=None, output=None):
        self.capture_path = Path(capture_path)
        self.seed = seed
        self.output = output or (lambda message: print(message, flush=True))
        self.sessions = {}
        self.connections = {}
        self.connection_errors = {}
        self.messages = []
        self.transcript = []
        self.errors = []
        self.unassigned_records = 0
        self.private_exponents = {}
        self.evidence = {}
        self.recovery_errors = {}
        self._offset = 0
        self._identity = None
        self._line_number = 0
        self._discarding = False
        self.has_partial_line = False

    def _error(self, message):
        message = _display(message)
        self.errors.append(message)
        self.output('Capture warning: ' + message)

    def _mark_connection_error(self, connection):
        if type(connection) is str:
            self.connection_errors[connection] = self.connection_errors.get(connection, 0) + 1
            session_id = self.connections.get(connection)
            if session_id is not None:
                self.sessions[session_id].error_count += 1

    def refresh(self):
        """Consume newly appended complete events; missing files mean waiting."""
        try:
            stream = self.capture_path.open('rb')
        except FileNotFoundError:
            if self._identity is not None:
                raise CaptureError('Capture file disappeared; restart with the new capture')
            return 0
        consumed = 0
        self.has_partial_line = False
        with stream:
            stat = self.capture_path.stat()
            identity = (stat.st_dev, stat.st_ino)
            if self._identity is not None and (identity != self._identity or stat.st_size < self._offset):
                raise CaptureError('Capture file was replaced or truncated; restart the tool')
            self._identity = identity
            stream.seek(self._offset)
            while True:
                start = stream.tell()
                line = stream.readline(MAX_CAPTURE_LINE + 1)
                if not line:
                    self.has_partial_line = self._discarding
                    break
                if self._discarding:
                    self._offset = stream.tell()
                    if line.endswith(b'\n'):
                        self._discarding = False
                        self._line_number += 1
                    continue
                if len(line) > MAX_CAPTURE_LINE:
                    self._error(f'line {self._line_number + 1} exceeds size limit')
                    self._offset = stream.tell()
                    self._discarding = not line.endswith(b'\n')
                    if not self._discarding:
                        self._line_number += 1
                    continue
                if not line.endswith(b'\n'):
                    # Read it again after the writer finishes the line.
                    self._offset = start
                    self.has_partial_line = True
                    break
                self._offset = stream.tell()
                self._line_number += 1
                consumed += 1
                event = None
                try:
                    event = json.loads(line.decode('utf-8'), object_pairs_hook=_unique_object)
                    self._ingest(event)
                except (ValueError, TypeError, KeyError, RecursionError) as error:
                    if type(event) is dict:
                        self._mark_connection_error(event.get('connection_id'))
                    self._error(f'line {self._line_number}: {error}')
        return consumed

    def _ingest(self, event):
        if type(event) is not dict:
            raise CaptureError('Event must be an object')
        if event.get('event') in ('capture_error', 'error'):
            self._mark_connection_error(event.get('connection_id'))
            self._error('capture process reported: ' + str(event.get('error', 'capture error')))
            return
        if event.get('event') != 'frame':
            return
        connection = event.get('connection_id')
        direction = event.get('direction')
        timestamp = event.get('time_ns')
        frame = event.get('frame')
        if (type(connection) is not str or not 1 <= len(connection) <= 128 or
                not connection.isprintable() or direction not in DIRECTIONS or
                type(timestamp) is not int or timestamp < 0 or type(frame) is not dict):
            raise CaptureError('Invalid frame event metadata')
        kind = frame.get('type')
        if kind == 'session':
            if set(frame) != {'type', 'header'} or direction != 'a_to_b':
                raise CaptureError('Session handshake must travel from A to B')
            header = validate_header(frame['header'])
            session_id = header['session_id']
            if connection in self.connections or session_id in self.sessions:
                raise CaptureError('Duplicate session handshake or reused session identifier')
            session = CapturedSession(header=header, connection_id=connection,
                                      error_count=self.connection_errors.get(connection, 0))
            self.sessions[session_id] = session
            self.connections[connection] = session_id
            self.output(f"Queued session {session_id[:8]}: {header['alice']} <-> {header['bob']}")
        elif kind == 'message':
            session_id = self.connections.get(connection)
            if session_id is None:
                self.unassigned_records += 1
                raise CaptureError('Message has no captured session handshake; cannot recover its key')
            session = self.sessions[session_id]
            validate_record(frame, session.header)
            if frame['direction'] != direction:
                raise CaptureError('Record direction differs from captured TCP direction')
            record = CapturedMessage(session_id, connection, frame, timestamp, len(self.messages))
            session.records.append(record)
            self.messages.append(record)
        elif kind not in ('public_key', 'ready'):
            raise CaptureError('Unknown wire frame type')

    def _show_evidence(self, evidence, private_exponent):
        self.output('Quantum measurement evidence · Qiskit Aer')
        for bits, count in sorted(evidence['counts'].items(), key=lambda item: (-item[1], item[0]))[:6]:
            self.output(f'  {bits}: {count}')
        self.output(f"Accepted sample: {evidence['sample']}; phase: {evidence['phase']:.6f}")
        self.output(f"Continued fraction: {evidence['convergent']}; order: {evidence['order']}")
        self.output(f"Recovered factors: {evidence['factors']}; RSA private exponent: {private_exponent}")
        self.output(f"Shots: {evidence['shots']}; elapsed: {evidence['elapsed_seconds']:.3f}s")

    def recover(self, retry=True):
        """Run quantum recovery once per public RSA key, then unwrap sessions."""
        self.refresh()
        recovered = 0
        for session_id, session in self.sessions.items():
            if session.master is not None:
                continue
            header = session.header
            public_key = (header['N'], header['e'])
            if public_key not in self.private_exponents:
                if public_key in self.recovery_errors and not retry:
                    continue
                self.output(f'Running Shor · N={public_key[0]} · base=5 ...')
                try:
                    evidence = run_factorization(seed=self.seed, modulus=public_key[0], base=5)
                    factors = evidence['factors']
                    if (type(factors) not in (list, tuple) or len(factors) != 2 or
                            any(type(x) is not int or not 1 < x < public_key[0] for x in factors)):
                        raise AttackFailure('Quantum recovery returned invalid factors')
                    p, q = factors
                    if p * q != public_key[0] or math.gcd(p, q) != 1:
                        raise AttackFailure('Quantum recovery returned invalid factors')
                    exponent = pow(public_key[1], -1, (p - 1) * (q - 1))
                    # Cache only after both evidence and arithmetic succeed.
                    self._show_evidence(evidence, exponent)
                    self.private_exponents[public_key] = exponent
                    self.evidence[public_key] = evidence
                    self.recovery_errors.pop(public_key, None)
                except (AttackFailure, ValueError, KeyError, TypeError, OSError) as error:
                    self.recovery_errors[public_key] = _display(error)
                    self.output(f'Recovery failed: {_display(error)}. Messages remain queued.')
                    # No second attempt for other sessions sharing this key in
                    # the same command, regardless of retry preference.
                    break
            try:
                session.master = recover_master(header, self.private_exponents[public_key])
                recovered += 1
                self.output(f'Session key recovered · {session_id[:8]}')
            except ValueError as error:
                self.output(f'Cannot unwrap session {session_id[:8]}: {_display(error)}')
        return recovered

    def decrypt_all(self, recover=True, retry=True):
        """Authenticate and emit new messages once, preserving capture order."""
        self.refresh()
        if recover:
            self.recover(retry=retry)
            # The independent packet-capture process keeps writing while the
            # simulator runs. Include that backlog before returning to a prompt.
            if self.refresh():
                self.recover(retry=False)
        added = []
        for record in self.messages:
            if record.processed:
                continue
            session = self.sessions[record.session_id]
            if session.master is None:
                continue
            frame = record.frame
            direction = frame['direction']
            expected = session.next_sequence[direction]
            try:
                if frame['sequence'] != expected:
                    reason = 'replayed/out-of-order record' if frame['sequence'] < expected else 'sequence gap; capture is incomplete'
                    raise CaptureError(f'{reason} (expected {expected}, got {frame["sequence"]})')
                text = decrypt_record(session.header, session.master, frame)
            except ValueError as error:
                record.error = _display(error)
                record.processed = True
                session.error_count += 1
                self.output(f'Rejected message in {record.session_id[:8]}: {record.error}')
                continue
            record.processed = True
            session.next_sequence[direction] += 1
            session.decrypted_count += 1
            sender = session.header['alice' if direction == 'a_to_b' else 'bob']
            receiver = session.header['bob' if direction == 'a_to_b' else 'alice']
            entry = {'session_id': record.session_id, 'connection_id': record.connection_id,
                     'time_ns': record.time_ns, 'direction': direction,
                     'sequence': frame['sequence'], 'sender': sender,
                     'receiver': receiver, 'text': text}
            self.transcript.append(entry)
            added.append(entry)
            self.output(f'[{record.session_id[:8]} {sender} -> {receiver}] {text}')
        return added

    def status(self):
        self.refresh()
        result = []
        for session_id, session in self.sessions.items():
            pending = sum(not record.processed for record in session.records)
            if session.master is None:
                state = 'WAITING_FOR_KEY_WITH_ERRORS' if session.error_count else 'WAITING_FOR_KEY'
            elif session.error_count:
                state = 'INCOMPLETE_OR_INVALID'
            elif pending:
                state = 'READY'
            else:
                state = 'DECRYPTED' if session.decrypted_count else 'KEY_RECOVERED'
            result.append({'session_id': session_id, 'connection_id': session.connection_id,
                           'alice': session.header['alice'], 'bob': session.header['bob'],
                           'captured': len(session.records), 'pending': pending,
                           'decrypted': session.decrypted_count, 'errors': session.error_count,
                           'state': state})
        return result

    def export(self, path):
        """Write authenticated plaintext only, without keys, to a new file."""
        destination = Path(path)
        if destination.resolve() == self.capture_path.resolve():
            raise CaptureError('Transcript destination must differ from the capture')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x', encoding='utf-8') as stream:
            for entry in self.transcript:
                stream.write(json.dumps(entry, ensure_ascii=True, separators=(',', ':')) + '\n')
        return len(self.transcript)


def print_status(queue):
    sessions = queue.status()
    if not sessions:
        queue.output('No sessions captured yet.')
    else:
        queue.output('SESSION   PEERS                  CAPTURED  PENDING  DECRYPTED  ERRORS  STATE')
        for session in sessions:
            peers = f"{session['alice']} <-> {session['bob']}"
            queue.output(f"{session['session_id'][:8]}  {peers:22} {session['captured']:8}  "
                         f"{session['pending']:7}  {session['decrypted']:9}  "
                         f"{session['errors']:6}  {session['state']}")
    if queue.unassigned_records:
        queue.output(f'{queue.unassigned_records} records missing a session handshake.')
    if queue.errors:
        queue.output(f'{len(queue.errors)} capture warning(s).')
    if queue.has_partial_line:
        queue.output('Waiting for an incomplete JSONL event.')


def _capture_health(process):
    if process is not None and process.poll() is not None:
        raise CaptureError(f'Live capture exited with code {process.returncode}; check the interface and capture prerequisites')


def follow(queue, process=None, return_to_prompt=True):
    ending = 'return' if return_to_prompt else 'exit'
    queue.output(f'Following messages · Ctrl+C to {ending}.')
    try:
        while True:
            _capture_health(process)
            queue.decrypt_all(retry=False)
            time.sleep(0.25)
    except KeyboardInterrupt:
        queue.output('\nStopped following.')


HELP = 'Commands: status | recover | decrypt-all | follow | export PATH | help | quit'


def interactive(queue, process=None):
    queue.output(HELP)
    while True:
        try:
            _capture_health(process)
            line = input('intercept> ').strip()
            if line in ('quit', 'exit'):
                return 0
            if line == 'status':
                print_status(queue)
            elif line == 'recover':
                queue.recover()
                print_status(queue)
            elif line == 'decrypt-all':
                queue.decrypt_all()
                print_status(queue)
            elif line == 'follow':
                follow(queue, process)
            elif line.startswith('export '):
                path = line[len('export '):].strip()
                # Accept an optionally quoted Windows path without interpreting
                # backslashes as shell escape characters.
                if len(path) >= 2 and path[0] == path[-1] and path[0] in ('"', "'"):
                    path = path[1:-1]
                count = queue.export(path)
                queue.output(f'Exported {count} authenticated messages to {_display(path)}')
            elif line in ('help', '?', ''):
                queue.output(HELP)
            else:
                queue.output('Unknown command. Type help.')
        except EOFError:
            return 0
        except KeyboardInterrupt:
            queue.output('\nExiting attacker tool.')
            return 0
        except (CaptureError, OSError, ValueError) as error:
            queue.output(f'Error: {_display(error)}')
            if process is not None and process.poll() is not None:
                return 1


def launch_dashboard(queue, process=None, interface=None, port=9001, *, follow_mode=False,
                     input=None, output=None):
    """Run the interceptor dashboard against an existing capture and queue.

    Capture-process ownership stays with the caller. In particular this works
    with a health adapter for a collector started by a different terminal.
    """
    from interceptor_controller import InterceptorController
    from interceptor_ui import InterceptorUI
    controller = InterceptorController(queue, process, interface=interface, port=port)
    ui = None
    def quit_dashboard():
        controller.close(wait=False)
        if ui is not None:
            ui.stop()
    ui = InterceptorUI(controller.submit, quit_dashboard, input=input, output=output)
    controller.attach_ui(ui)
    try:
        controller.start()
        if follow_mode:
            controller.submit('follow')
        ui.run()
    finally:
        ui.stop()
        if not controller.close(wait=True):
            raise RuntimeError('Interceptor worker did not stop within its quantum deadline')
    return 0


def _wait_capture_ready(process, queue):
    """Drain capture output and require readiness before starting the prompt."""
    ready = threading.Event()
    def drain():
        for line in process.stdout:
            queue.output(_display(line.rstrip('\r\n')))
            if line.startswith('Capture ready '):
                ready.set()
    threading.Thread(target=drain, daemon=True).start()
    deadline = time.monotonic() + 15
    while not ready.wait(0.05):
        _capture_health(process)
        if time.monotonic() >= deadline:
            raise CaptureError('Live capture did not become ready within 15 seconds')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', default='captures/chat.jsonl', help='Public capture JSONL file')
    parser.add_argument('--live', action='store_true', help='Start a separate passive packet capture process')
    parser.add_argument('--interface', help='Capture interface name; see capture.py --list-interfaces')
    parser.add_argument('--port', type=int, default=9001, help='Chat TCP port for live capture')
    parser.add_argument('--seed', type=int, help='Optional reproducible Aer simulator seed')
    parser.add_argument('--plain', action='store_true', help='Use the plain command prompt instead of the dashboard')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--decrypt-all', action='store_true', help='Recover and decrypt the existing capture, then exit')
    mode.add_argument('--follow', action='store_true', help='Recover and decrypt continually until Ctrl+C')
    args = parser.parse_args(argv)
    if args.live and not args.interface:
        parser.error('--live requires --interface; use capture.py --list-interfaces')
    if args.live and args.decrypt_all:
        parser.error('--live requires interactive mode or --follow, so capture can collect the handshake')
    if not 1 <= args.port <= 65535:
        parser.error('--port must be in 1..65535')
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    process = None
    queue = CaptureQueue(args.capture, seed=args.seed)
    try:
        if args.live:
            command = [sys.executable, str(Path(__file__).with_name('capture.py')),
                       '--interface', args.interface, '--port', str(args.port),
                       '--output', args.capture]
            queue.output(f'Starting capture · {args.interface} · TCP {args.port} ...')
            options = ({'creationflags': subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
                       if sys.platform == 'win32'
                       else {'start_new_session': True})
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding='utf-8', errors='replace', **options)
            _wait_capture_ready(process, queue)
        if args.decrypt_all:
            queue.decrypt_all()
            sessions = queue.status()
            print_status(queue)
            return 0 if sessions and not queue.errors and not queue.unassigned_records and not queue.has_partial_line and all(
                session['pending'] == 0 and session['errors'] == 0 and session['state'] in
                ('DECRYPTED', 'KEY_RECOVERED') for session in sessions) else 1
        if not args.plain and sys.stdin.isatty() and sys.stdout.isatty():
            return launch_dashboard(queue, process, args.interface, args.port, follow_mode=args.follow)
        if args.follow:
            follow(queue, process, return_to_prompt=False)
        else:
            return interactive(queue, process)
        return 0
    except (CaptureError, OSError, ValueError) as error:
        queue.output(f'Error: {_display(error)}')
        return 1
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    raise SystemExit(main())
