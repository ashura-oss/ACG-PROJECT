"""Purpose-built passive interception dashboard; no decryption happens here."""
import asyncio
from collections import deque
from copy import deepcopy
from datetime import datetime
import threading

from prompt_toolkit import Application
from prompt_toolkit.document import Document
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import DynamicContainer, HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.styles import Style
from prompt_toolkit.utils import get_cwidth
from prompt_toolkit.widgets import Frame, TextArea


def _text(value):
    return ''.join(char if char.isprintable() else repr(char)[1:-1] for char in str(value))


def _fit(value, width):
    value = _text(value)
    if get_cwidth(value) <= width:
        return value
    result = ''
    for char in value:
        if get_cwidth(result + char) >= width:
            break
        result += char
    return result + '…'


def _count(value):
    return value if type(value) is int and value >= 0 else 0


def _rows(value):
    return [row for row in value if type(row) is dict] if type(value) is list else []


class _PaneLexer(Lexer):
    def __init__(self, owner, pane):
        self.owner, self.pane = owner, pane

    def lex_document(self, document):
        lines = self.owner._pane_lines[self.pane]
        return lambda number: lines[number] if number < len(lines) else [('', '')]


class InterceptorUI:
    """Thread-safe display fed by a capture/decryption controller snapshot.

    Only snapshot.transcript is eligible for plaintext display. Traffic entries
    contain ciphertext and rejection metadata, never trusted plaintext. The
    controller remains responsible for AES authentication before transcription.
    """
    def __init__(self, on_command, on_quit, *, input=None, output=None):
        self.on_command, self.on_quit = on_command, on_quit
        self.snapshot = {'capture_state': 'READING', 'capture_name': '',
                         'interface': None, 'port': None, 'busy': None,
                         'follow': False, 'sessions': [], 'transcript': [],
                         'traffic': [], 'evidence': [], 'errors': 0}
        self._lock = threading.RLock()
        self._loop = None
        self._owner_thread = None
        self._running = False
        self._stop_requested = False
        self._quit_called = False
        self._command_feedback = ''
        self.activity_log = deque(maxlen=200)
        self._pane_lines = {name: [] for name in ('queue', 'traffic', 'quantum', 'activity')}
        self._follow_tail = {'queue': False, 'traffic': True, 'quantum': False, 'activity': True}
        self._selected_pane = 'traffic'
        self._views = {name: TextArea(read_only=True, focusable=False,
                                     wrap_lines=True, scrollbar=True,
                                     lexer=_PaneLexer(self, name), style='class:panel')
                       for name in self._pane_lines}
        self.session_view = self._views['queue']
        self.traffic_view = self._views['traffic']
        self.quantum_view = self._views['quantum']
        self.activity_view = self._views['activity']
        self.composer = TextArea(multiline=False, wrap_lines=False, height=1,
                                 prompt=' > ', style='class:composer')
        bindings = KeyBindings()

        @bindings.add('enter')
        def command(event):
            self._command(self.composer.text.strip(), clear_input=True)

        @bindings.add('f2')
        def recover(event):
            self._command('recover')

        @bindings.add('f3')
        def decrypt(event):
            self._command('decrypt-all')

        @bindings.add('f4')
        def follow(event):
            self._command('unfollow' if self.snapshot.get('follow') else 'follow')

        @bindings.add('c-c')
        @bindings.add('c-d')
        def quit_dashboard(event):
            self._request_quit()

        @bindings.add('tab')
        def next_pane(event):
            self._cycle_pane(1)

        @bindings.add('s-tab')
        def previous_pane(event):
            self._cycle_pane(-1)

        @bindings.add('pageup')
        def page_up(event):
            self._scroll(-1)

        @bindings.add('pagedown')
        def page_down(event):
            self._scroll(1)

        @bindings.add('c-end')
        def latest(event):
            view = self._views[self._selected_pane]
            self._follow_tail[self._selected_pane] = True
            view.buffer.cursor_position = len(view.text)

        def heading(name, title):
            return Window(FormattedTextControl(lambda: self._heading(name, title)),
                          height=1, style='class:panel-title')

        compact = HSplit([
            heading('queue', 'SESSION QUEUE'),
            self.session_view,
            heading('traffic', 'TRAFFIC'),
            self.traffic_view,
            heading('quantum', 'QUANTUM EVIDENCE · Qiskit Aer'),
            self.quantum_view,
            heading('activity', 'ACTIVITY'),
            self.activity_view,
        ])
        self.session_view.window.height = Dimension(min=1, preferred=3, max=5)
        self.traffic_view.window.height = Dimension(min=2, weight=3)
        self.quantum_view.window.height = Dimension(min=2, preferred=4, max=8)
        self.activity_view.window.height = Dimension(min=1, preferred=2)
        wide = HSplit([
            Frame(self.session_view, title=lambda: self._heading_text('queue', 'SESSION QUEUE'),
                  style='class:frame'),
            VSplit([
                Frame(self.traffic_view, title=lambda: self._heading_text('traffic', 'TRAFFIC'),
                      style='class:frame'),
                HSplit([
                    Frame(self.quantum_view,
                          title=lambda: self._heading_text('quantum', 'QUANTUM EVIDENCE · Qiskit Aer'),
                          style='class:frame'),
                    Frame(self.activity_view,
                          title=lambda: self._heading_text('activity', 'ACTIVITY'),
                          style='class:frame'),
                ], width=Dimension(min=36, preferred=45, max=54)),
            ], padding=1),
        ])
        def choose_body():
            # Layout walks its children before Application has been assigned.
            current_output = self.app.output if hasattr(self, 'app') else output
            columns = current_output.get_size().columns if current_output is not None else 80
            return wide if columns >= 112 else compact
        body = DynamicContainer(choose_body)
        layout = HSplit([
            Window(FormattedTextControl(self._header), height=1, style='class:header'),
            Window(FormattedTextControl(self._source_line), height=1, style='class:subheader'),
            Window(FormattedTextControl(self._totals), height=1, style='class:totals'),
            body,
            Frame(self.composer, title=' Command ', style='class:frame'),
            Window(FormattedTextControl(self._footer), height=1, style='class:footer'),
        ])
        self.app = Application(layout=Layout(layout, focused_element=self.composer),
                               key_bindings=bindings, full_screen=True,
                               input=input, output=output, mouse_support=False,
                               min_redraw_interval=0.04,
                               style=Style.from_dict({
                                   '': 'bg:#0b1220 #e2e8f0',
                                   'header': 'bg:#162235 #e2e8f0',
                                   'brand': 'bg:#162235 #5eead4 bold',
                                   'live': 'bg:#162235 #5eead4',
                                   'reading': 'bg:#162235 #93c5fd',
                                   'stopped': 'bg:#162235 #94a3b8',
                                   'capture-error': 'bg:#162235 #fca5a5 bold',
                                   'busy': 'bg:#162235 #fbbf24',
                                   'follow': 'bg:#162235 #5eead4',
                                   'subheader': 'bg:#162235 #94a3b8',
                                   'totals': 'bg:#111c2e #cbd5e1',
                                   'panel': 'bg:#0b1220 #e2e8f0',
                                   'panel-title': 'bg:#162235 #93c5fd bold',
                                   'selected-title': 'bg:#162235 #5eead4 bold',
                                   'frame': '#334b65',
                                   'frame.label': '#93c5fd',
                                   'muted': '#64748b',
                                   'pending': '#fbbf24',
                                   'read': '#5eead4',
                                   'error': '#fca5a5',
                                   'message': '#e2e8f0',
                                   'metadata': '#93c5fd',
                                   'evidence': '#c4b5fd',
                                   'composer': 'bg:#111c2e #f8fafc',
                                   'footer': '#94a3b8',
                                   'scrollbar.background': '#162235',
                                   'scrollbar.button': '#5eead4',
                               }))
        self._render_snapshot()
        self._append_log('Ready. Capture traffic, then recover and decrypt the queue.')

    def _header(self):
        state = self.snapshot.get('capture_state', 'READING')
        if state not in ('LIVE', 'READING', 'STOPPED', 'ERROR'):
            state = 'ERROR'
        style = {'LIVE': 'live', 'READING': 'reading', 'STOPPED': 'stopped', 'ERROR': 'capture-error'}[state]
        fragments = [('class:brand', '  INTERCEPTOR  '), (f'class:{style}', f'● {state}')]
        if self.snapshot.get('busy'):
            fragments.append(('class:busy', '  |  ' + _fit(self.snapshot['busy'], 27)))
        if self.snapshot.get('follow'):
            fragments.append(('class:follow', '  |  FOLLOW ON'))
        return fragments

    def _source_line(self):
        name = _text(self.snapshot.get('capture_name') or 'Waiting for capture')
        interface = self.snapshot.get('interface')
        port = self.snapshot.get('port')
        suffix = ('  ·  ' + _text(interface)) if interface else ''
        if type(port) is int:
            suffix += f'  ·  TCP {port}'
        return '  ' + _fit(name + suffix, max(10, self.app.output.get_size().columns - 3))

    def _totals(self):
        sessions = _rows(self.snapshot.get('sessions'))
        captured = sum(_count(row.get('captured')) for row in sessions)
        pending = sum(_count(row.get('pending')) for row in sessions)
        read = sum(_count(row.get('decrypted')) for row in sessions)
        session_label = 'session' if len(sessions) == 1 else 'sessions'
        return (f'  {len(sessions)} {session_label}   {captured} captured   {pending} queued'
                f'   {read} decrypted   {_count(self.snapshot.get("errors"))} errors')

    def _footer(self):
        text = '  F2 recover  F3 decrypt-all  F4 follow  ·  Tab pane  PgUp/PgDn scroll'
        if self._command_feedback:
            text = '  ' + self._command_feedback
        return _fit(text, max(10, self.app.output.get_size().columns))

    def _heading_text(self, name, title):
        return (' ▸ ' if name == self._selected_pane else '   ') + title + ' '

    def _heading(self, name, title):
        style = 'class:selected-title' if name == self._selected_pane else 'class:panel-title'
        return [(style, self._heading_text(name, title))]

    def _dispatch(self, callback):
        with self._lock:
            if self._running and threading.get_ident() != self._owner_thread:
                try:
                    self._loop.call_soon_threadsafe(self._apply, callback)
                    return
                except RuntimeError:
                    if not self._loop.is_closed():
                        raise
            self._apply(callback)

    def _apply(self, callback):
        with self._lock:
            callback()
            self.app.invalidate()

    def _set_pane(self, name, lines):
        self._pane_lines[name] = lines
        view = self._views[name]
        text = '\n'.join(''.join(fragment[1] for fragment in line) for line in lines)
        position = len(text) if self._follow_tail[name] else min(view.buffer.cursor_position, len(text))
        view.buffer.set_document(Document(text, position), bypass_readonly=True)

    def update(self, snapshot):
        if type(snapshot) is not dict:
            self.log('Invalid dashboard update ignored.')
            return
        copied = deepcopy(snapshot)
        def apply_snapshot():
            self.snapshot = copied
            self._render_snapshot()
        self._dispatch(apply_snapshot)

    def _render_snapshot(self):
        sessions = _rows(self.snapshot.get('sessions'))
        queue_lines = [[('class:muted', ' SESSION   PEERS                      QUEUED  READ  STATE')]]
        states = {'WAITING_FOR_KEY': 'WAITING', 'WAITING_FOR_KEY_WITH_ERRORS': 'WAITING / ERROR',
                  'KEY_RECOVERED': 'KEY READY', 'INCOMPLETE_OR_INVALID': 'INCOMPLETE'}
        if not sessions:
            queue_lines = [[('class:muted', ' No sessions yet. Start capture before connecting the chat.')]]
        for session in sessions:
            identifier = _fit(session.get('session_id', '?'), 8)
            peers = _fit(f"{_text(session.get('alice', '?'))} ↔ {_text(session.get('bob', '?'))}", 25)
            peers += ' ' * max(0, 25 - get_cwidth(peers))
            raw_state = _text(session.get('state', 'WAITING_FOR_KEY'))
            state = states.get(raw_state, raw_state)
            style = 'error' if _count(session.get('errors')) or 'ERROR' in raw_state or 'INVALID' in raw_state else (
                'read' if raw_state in ('DECRYPTED', 'KEY_RECOVERED', 'READY') else 'pending')
            queue_lines.append([('class:metadata', f' {identifier:8}  '), ('class:message', peers),
                                ('class:message', f' {_count(session.get("pending")):6}  {_count(session.get("decrypted")):4}  '),
                                (f'class:{style}', state)])
        self._set_pane('queue', queue_lines)
        self._render_traffic()
        self._render_quantum()

    def _render_traffic(self):
        transcript = []
        for row in _rows(self.snapshot.get('transcript')):
            if (row.get('error') or row.get('authenticated') is False or
                    not all(type(row.get(key)) is str for key in ('session_id', 'direction', 'sender', 'receiver', 'text')) or
                    row['direction'] not in ('a_to_b', 'b_to_a') or type(row.get('sequence')) is not int or row['sequence'] < 0):
                continue
            transcript.append(row)
        authenticated = {(row['session_id'], row['direction'], row['sequence']): row for row in transcript}
        displayed = set()
        lines = []
        for row in _rows(self.snapshot.get('traffic')):
            sid = _text(row.get('session_id', '?'))
            direction = row.get('direction')
            if direction not in ('a_to_b', 'b_to_a') or type(row.get('sequence')) is not int or row['sequence'] < 0:
                lines.append([('class:error', ' Invalid captured record')])
                continue
            key = (sid, direction, row['sequence'])
            route = 'A → B' if direction == 'a_to_b' else 'B → A'
            prefix = f' {sid[:8]}  {route}  #{row["sequence"]}'
            if row.get('error'):
                lines.append([('class:error', prefix + '  REJECTED')])
                lines.append([('class:error', '   ' + _fit(row['error'], 180))])
            elif key in authenticated:
                if key not in displayed:
                    self._plaintext_lines(lines, authenticated[key])
                    displayed.add(key)
            else:
                state = 'NOT DECRYPTED' if row.get('processed') else 'QUEUED'
                lines.append([('class:pending', prefix + '  ' + state)])
                # Deliberately ignore any untrusted traffic.text field.
                lines.append([('class:muted', '   ' + _fit(row.get('ciphertext_preview') or 'Ciphertext captured', 120))])
            lines.append([('', '')])
        for row in transcript:
            key = (row['session_id'], row['direction'], row['sequence'])
            if key not in displayed:
                self._plaintext_lines(lines, row)
                lines.append([('', '')])
                displayed.add(key)
        if not lines:
            lines = [[('class:muted', ' Waiting for encrypted traffic.')],
                     [('class:muted', ' Captured ciphertext appears here before decryption.')]]
        self._set_pane('traffic', lines)

    def _plaintext_lines(self, lines, row):
        lines.append([('class:read', f' {row["session_id"][:8]}  ' + _text(row['sender']) + ' → ' +
                       _text(row['receiver']) + f'  #{row["sequence"]}  DECRYPTED')])
        lines.append([('class:message', '   ' + _text(row['text']))])

    def _render_quantum(self):
        evidence_rows = _rows(self.snapshot.get('evidence'))
        if not evidence_rows:
            busy = self.snapshot.get('busy')
            text = (('Order finding in progress…' if busy in ('Recovering RSA key', 'Decrypting queue')
                     else _text(busy) + '…') if busy else 'No quantum measurements yet. F2 starts recovery.')
            self._set_pane('quantum', [[('class:pending' if self.snapshot.get('busy') else 'class:muted', ' ' + text)]])
            return
        evidence = evidence_rows[-1]
        factors = evidence.get('factors')
        factor_text = ' × '.join(map(str, factors)) if type(factors) in (list, tuple) else '—'
        phase = evidence.get('phase')
        phase_text = f'{phase:.6f}' if type(phase) in (int, float) else '—'
        elapsed = evidence.get('elapsed_seconds')
        elapsed_text = f'{elapsed:.2f}s' if type(elapsed) in (int, float) else '—'
        convergent = evidence.get('convergent')
        fraction = '/'.join(map(str, convergent)) if type(convergent) in (list, tuple) else '—'
        lines = [[('class:evidence', f' N={_text(evidence.get("N", 33))}  order {_text(evidence.get("order", "—"))}  factors {_text(factor_text)}')],
                 [('class:metadata', f' {_count(evidence.get("shots")):,} shots  ·  {_text(elapsed_text)}  ·  fraction {_text(fraction)}')],
                 [('class:message', f' Sample {_text(evidence.get("sample", "—"))}  phase {_text(phase_text)}')]]
        counts = evidence.get('counts')
        if type(counts) is dict:
            valid_counts = [(bits, count) for bits, count in counts.items()
                            if type(bits) is str and type(count) is int and count >= 0]
            for bits, count in sorted(valid_counts, key=lambda item: (-item[1], item[0]))[:4]:
                lines.append([('class:muted', f' {_text(bits)}  '), ('class:evidence', f'{count:,}')])
        self._set_pane('quantum', lines)

    def _append_log(self, text):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.activity_log.append((timestamp, _text(text)[:2000]))
        self._set_pane('activity', [[('class:muted', f' {stamp}  '), ('class:message', message)]
                                    for stamp, message in self.activity_log])

    def log(self, text):
        self._dispatch(lambda: self._append_log(text))

    def clear_log(self):
        def clear():
            self.activity_log.clear()
            self._set_pane('activity', [])
        self._dispatch(clear)

    def _command(self, command, clear_input=False):
        if command in ('quit', '/quit', 'exit'):
            self._request_quit()
            return
        if not command:
            return
        try:
            accepted = self.on_command(command)
        except (OSError, ValueError) as error:
            self._append_log(str(error))
            accepted = False
        if accepted:
            if clear_input:
                self.composer.buffer.set_document(Document('', 0))
            self._command_feedback = ''
        else:
            self._command_feedback = 'Command not accepted. Edit and try again.'

    def _cycle_pane(self, direction):
        panes = tuple(self._views)
        self._selected_pane = panes[(panes.index(self._selected_pane) + direction) % len(panes)]

    def _scroll(self, direction):
        view = self._views[self._selected_pane]
        document = view.buffer.document
        info = view.window.render_info
        distance = max(1, info.window_height - 1) if info else 5
        row = min(max(0, document.cursor_position_row + direction * distance), document.line_count - 1)
        view.buffer.cursor_position = document.translate_row_col_to_index(row, 0)
        self._follow_tail[self._selected_pane] = direction > 0 and row == document.line_count - 1

    def _request_quit(self):
        if self._quit_called:
            return
        self._quit_called = True
        try:
            self.on_quit()
        finally:
            self.stop()

    def stop(self):
        def exit_app():
            self._stop_requested = True
            if self.app.is_running and not self.app.is_done:
                self.app.exit()
        self._dispatch(exit_app)

    def _on_start(self):
        with self._lock:
            self.app.output.set_title('Interceptor')
            self._loop = asyncio.get_running_loop()
            self._owner_thread = threading.get_ident()
            self._running = True
            if self._stop_requested:
                self.app.exit()

    def run(self):
        with self._lock:
            if self._stop_requested:
                return
        try:
            self.app.run(pre_run=self._on_start)
        finally:
            with self._lock:
                self._running = False
                self._loop = None
                self._owner_thread = None
