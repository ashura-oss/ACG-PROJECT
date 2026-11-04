"""Serialize capture work behind an independently responsive interceptor UI."""
import copy
from pathlib import Path
import queue as command_queue
import threading


HELP = 'status · recover · decrypt-all · follow · unfollow · export PATH · clear · help · quit'


class InterceptorController:
    """One worker owns the CaptureQueue; UI callbacks only submit commands.

    Live packet collection belongs to a separate process. It continues while
    this worker waits for the bounded quantum-factorization child process.
    Closing waits at most 35 seconds for that existing 30-second deadline; it
    never searches for or terminates unrelated processes.
    """

    def __init__(self, queue, process=None, *, interface=None, port=9001):
        self.queue = queue
        self.process = process
        self.interface = interface
        self.port = port
        self.ui = None
        self._commands = command_queue.Queue(maxsize=32)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._thread = None
        self._busy = None
        self._follow = False
        self._feedback = 'Ready'
        self._read_error = None
        self._last_health = None
        self._blocked_sessions = set()
        self._snapshot = {}
        self._previous_output = queue.output

    def attach_ui(self, ui):
        if self._thread is not None:
            raise RuntimeError('Attach the UI before starting the controller')
        self.ui = ui
        self.queue.output = self._log
        return self

    def start(self):
        if self._thread is not None:
            return self
        if self.ui is None:
            raise RuntimeError('Attach an interceptor UI before starting')
        self._idle.clear()
        self._thread = threading.Thread(target=self._run, name='acg-interceptor-worker', daemon=True)
        self._thread.start()
        return self

    def _log(self, text):
        if self.ui is not None:
            self.ui.log(str(text))

    def submit(self, command):
        """Return promptly; never read captures or run quantum work on the UI."""
        if (type(command) is not str or len(command) > 4096 or
                any(not char.isprintable() for char in command)):
            self._log('Invalid command.')
            return False
        command = command.strip()
        if command in ('quit', 'exit'):
            self.close(wait=False)
            if self.ui is not None:
                self.ui.stop()
            return True
        if self._stop.is_set():
            return False
        if not command:
            return True
        if command not in ('status', 'recover', 'decrypt-all', 'follow', 'unfollow', 'clear', 'help', '?') and not command.startswith('export '):
            self._log('Unknown command. Type help.')
            return False
        try:
            self._idle.clear()
            self._commands.put_nowait(command)
        except command_queue.Full:
            self._log('Command queue is full. Wait for the current operation.')
            return False
        return True

    def close(self, wait=True):
        """Stop scheduling work; return whether the worker has finished.

        A currently running Shor call retains its own subprocess deadline and
        cleanup. No packet-capture process is stopped here: its owner controls
        that lifecycle, including when an existing capture is attached.
        """
        self._stop.set()
        if self._thread is None:
            self.queue.output = self._previous_output
            return True
        if wait and threading.current_thread() is not self._thread:
            self._thread.join(timeout=35)
        stopped = not self._thread.is_alive()
        if stopped:
            self.queue.output = self._previous_output
        return stopped

    def wait_idle(self, timeout=5):
        """Useful to synchronize headless clients without touching the queue."""
        return self._idle.wait(timeout)

    def snapshot(self):
        """Return the last published, independent snapshot without queue access."""
        with self._lock:
            return copy.deepcopy(self._snapshot)

    def _capture_state(self):
        if self._stop.is_set():
            return 'STOPPED'
        if self._read_error is not None:
            return 'ERROR'
        if self.process is None:
            return 'READING'
        try:
            code = self.process.poll()
        except OSError as error:
            self._health_feedback(f'Capture error: {error}')
            return 'ERROR'
        if code is None:
            return 'LIVE'
        if code:
            self._health_feedback(f'Capture stopped with code {code}. Captured data remains available.')
            return 'ERROR'
        self._health_feedback('Capture stopped. Captured data remains available.')
        return 'STOPPED'

    def _health_feedback(self, message):
        if message != self._last_health:
            self._last_health = message
            self._feedback = message
            self._log(message)

    def _publish(self):
        try:
            sessions = self.queue.status()
        except (ValueError, OSError) as error:
            self._read_error = str(error)
            sessions = self._snapshot.get('sessions', [])
        traffic = []
        for record in self.queue.messages[-100:]:
            ciphertext = record.frame.get('ciphertext_and_tag_hex', '')
            preview = ciphertext[:48] + ('…' if len(ciphertext) > 48 else '')
            traffic.append({'session_id': record.session_id,
                            'direction': record.frame.get('direction'),
                            'sequence': record.frame.get('sequence'),
                            'ciphertext_preview': preview,
                            'error': record.error, 'processed': record.processed})
        evidence = [dict(copy.deepcopy(value), N=public[0], e=public[1],
                         private_exponent=self.queue.private_exponents.get(public))
                    for public, value in self.queue.evidence.items()]
        snapshot = {'capture_state': self._capture_state(),
                    'capture_name': Path(self.queue.capture_path).name,
                    'interface': self.interface,
                    'port': self.port,
                    'busy': self._busy,
                    'follow': self._follow,
                    'sessions': copy.deepcopy(sessions),
                    'transcript': copy.deepcopy(self.queue.transcript),
                    'traffic': traffic, 'evidence': evidence,
                    'errors': len(self.queue.errors) + len(self.queue.recovery_errors) +
                              sum(record.error is not None for record in self.queue.messages) +
                              int(self._read_error is not None),
                    'feedback': self._feedback,
                    'queue_depth': self._commands.qsize()}
        with self._lock:
            self._snapshot = snapshot
        self.ui.update(copy.deepcopy(snapshot))

    def _refresh(self):
        try:
            self.queue.refresh()
            self._read_error = None
        except (ValueError, OSError) as error:
            message = str(error)
            if message != self._read_error:
                self._feedback = f'Capture error: {message}'
                self._log(self._feedback)
            self._read_error = message

    def _job(self, name, operation):
        self._busy = name
        self._idle.clear()
        self._publish()
        try:
            result = operation()
            return result
        finally:
            self._busy = None

    def _decrypt(self, retry):
        before = len(self.queue.transcript)
        self._job('Decrypting queue', lambda: self.queue.decrypt_all(retry=retry))
        self._blocked_sessions.update(session_id for session_id, session in self.queue.sessions.items()
                                      if session.master is None)
        added = len(self.queue.transcript) - before
        self._feedback = (f'{added} message(s) decrypted' if added else
                          'Key recovery failed' if self.queue.recovery_errors else 'No new messages decrypted')

    def _execute(self, command):
        if command == 'status':
            self._refresh()
            self._feedback = 'Status updated'
        elif command == 'recover':
            self._blocked_sessions.clear()
            recovered = self._job('Recovering RSA key', self.queue.recover)
            self._feedback = ('Key recovery failed' if self.queue.recovery_errors else
                              f'{recovered} session key(s) recovered')
        elif command == 'decrypt-all':
            self._blocked_sessions.clear()
            self._decrypt(retry=True)
        elif command == 'follow':
            self._follow = True
            self._feedback = 'Following new messages'
        elif command == 'unfollow':
            self._follow = False
            self._feedback = 'Follow paused'
        elif command.startswith('export '):
            path = command[len('export '):].strip()
            if len(path) >= 2 and path[0] == path[-1] and path[0] in ('"', "'"):
                path = path[1:-1]
            count = self._job('Exporting transcript', lambda: self.queue.export(path))
            self._feedback = f'Exported {count} message(s) to {path}'
            self._log(self._feedback)
        elif command == 'clear':
            clear = getattr(self.ui, 'clear_log', None)
            if clear is not None:
                clear()
            self._feedback = 'Activity cleared'
        elif command in ('help', '?'):
            self._log(HELP)
            self._feedback = 'Commands listed in activity'
        else:
            self._feedback = 'Unknown command. Type help.'
            self._log(self._feedback)

    def _follow_ready(self):
        if not self._follow or self._stop.is_set() or self._read_error is not None:
            return False
        # Avoid repainting a fictitious job every poll when no new records exist.
        # A failed quantum public key is skipped until an explicit retry command.
        for record in self.queue.messages:
            if record.processed or record.session_id in self._blocked_sessions:
                continue
            session = self.queue.sessions[record.session_id]
            public = (session.header['N'], session.header['e'])
            if session.master is not None or public not in self.queue.recovery_errors:
                return True
        return False

    def _run(self):
        try:
            while not self._stop.is_set():
                self._refresh()
                command = None
                try:
                    command = self._commands.get(timeout=0.25)
                    if not self._stop.is_set():
                        self._execute(command)
                except command_queue.Empty:
                    pass
                except (ValueError, OSError, RuntimeError) as error:
                    self._feedback = f'Error: {error}'
                    self._log(self._feedback)
                finally:
                    if command is not None:
                        self._commands.task_done()
                if self._follow_ready():
                    try:
                        self._decrypt(retry=False)
                    except (ValueError, OSError, RuntimeError) as error:
                        self._feedback = f'Error: {error}'
                        self._log(self._feedback)
                self._publish()
                if self._commands.empty() and self._busy is None:
                    self._idle.set()
        finally:
            self._busy = None
            self._publish()
            self._idle.set()
