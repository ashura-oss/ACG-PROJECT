"""Interactive chat screen. Transport and cryptography remain in chat.py."""
import asyncio
from dataclasses import dataclass
from datetime import datetime
import sys
import threading

from prompt_toolkit import Application
from prompt_toolkit.document import Document
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.styles import Style
from prompt_toolkit.utils import get_cwidth
from prompt_toolkit.widgets import Frame, TextArea


def is_interactive_terminal():
    """Piped processes keep their plain, line-oriented interface."""
    return bool(getattr(sys.stdin, 'isatty', lambda: False)() and
                getattr(sys.stdout, 'isatty', lambda: False)())


def _display(value):
    return ''.join(character if character.isprintable() else repr(character)[1:-1]
                   for character in str(value))


def _fit_label(value, width):
    if get_cwidth(value) <= width:
        return value
    prefix = ''
    for character in value:
        if get_cwidth(prefix + character) >= width:
            break
        prefix += character
    return prefix + '…'


@dataclass
class _Entry:
    timestamp: str
    sender: str
    text: str
    outgoing: bool | None


class _TranscriptLexer(Lexer):
    def __init__(self, owner):
        self.owner = owner

    def lex_document(self, document):
        # Each renderer receives an immutable snapshot while updates continue.
        lines = self.owner._formatted_lines
        return lambda number: lines[number] if number < len(lines) else [('', '')]


class TerminalChatUI:
    """A persistent composer and independently scrollable conversation.

    message/notice/set_disconnected/stop may be called from a receiver thread.
    on_send executes in the UI thread and must return True only after sending.
    It may call notice with a short validation error before returning False.
    """
    def __init__(self, own_name, peer_name, session_id, on_send, on_quit,
                 *, input=None, output=None):
        self.own_name = _display(own_name)
        self.peer_name = _display(peer_name)
        self.session_id = str(session_id)
        self.on_send = on_send
        self.on_quit = on_quit
        self.connected = True
        self.sent_count = 0
        self.received_count = 0
        self._entries = []
        self._formatted_lines = []
        self._follow_tail = True
        self._feedback = ''
        self._lock = threading.RLock()
        self._loop = None
        self._owner_thread = None
        self._running = False
        self._stop_requested = False
        self._quit_called = False

        self.transcript = TextArea(read_only=True, focusable=False,
                                   lexer=_TranscriptLexer(self), wrap_lines=True,
                                   scrollbar=True, style='class:transcript')
        self.composer = TextArea(multiline=False, wrap_lines=True,
                                 height=Dimension(min=2, preferred=3, max=3),
                                 prompt='  > ', style='class:composer')
        bindings = KeyBindings()

        @bindings.add('enter')
        def send(event):
            self._submit()

        @bindings.add('c-c')
        @bindings.add('c-d')
        def quit_chat(event):
            self._request_quit()

        @bindings.add('pageup')
        def page_up(event):
            self._scroll(-1)

        @bindings.add('pagedown')
        def page_down(event):
            self._scroll(1)

        @bindings.add('c-end')
        def latest(event):
            self._follow_tail = True
            self.transcript.buffer.cursor_position = len(self.transcript.text)

        layout = HSplit([
            Window(FormattedTextControl(self._header), height=1, style='class:header'),
            Window(FormattedTextControl(self._session_line), height=1, style='class:subheader'),
            Window(height=1, char='─', style='class:rule'),
            self.transcript,
            Window(FormattedTextControl(self._counts_line), height=1, style='class:counts'),
            Frame(self.composer, title=lambda: f' Message to {self.peer_name} ',
                  style='class:compose-frame'),
            Window(FormattedTextControl(self._footer), height=1, style='class:footer'),
        ])
        self.app = Application(layout=Layout(layout, focused_element=self.composer),
                               key_bindings=bindings, full_screen=True,
                               mouse_support=False, input=input, output=output,
                               min_redraw_interval=0.03,
                               style=Style.from_dict({
                                   '': 'bg:#0b1220 #e2e8f0',
                                   'header': 'bg:#162235 #e2e8f0',
                                   'brand': 'bg:#162235 #5eead4 bold',
                                   'peer': 'bg:#162235 #f8fafc bold',
                                   'connected': 'bg:#162235 #5eead4',
                                   'offline': 'bg:#162235 #fbbf24',
                                   'subheader': 'bg:#162235 #94a3b8',
                                   'rule': '#26374c',
                                   'transcript': 'bg:#0b1220 #e2e8f0',
                                   'timestamp': '#64748b',
                                   'outgoing': '#5eead4 bold',
                                   'incoming': '#93c5fd bold',
                                   'message': '#e2e8f0',
                                   'notice': '#94a3b8 italic',
                                   'counts': 'bg:#111c2e #94a3b8',
                                   'compose-frame': '#334b65',
                                   'frame.label': '#93c5fd',
                                   'composer': 'bg:#111c2e #f8fafc',
                                   'footer': '#94a3b8',
                                   'scrollbar.background': '#162235',
                                   'scrollbar.button': '#5eead4',
                               }))

    def _header(self):
        state_style = 'class:connected' if self.connected else 'class:offline'
        state = 'CONNECTED' if self.connected else 'OFFLINE'
        brand, separator, status = '  ACG CHAT  ', '  ↔  ', f'    ● {state}'
        width = self.app.output.get_size().columns
        available = max(2, width - get_cwidth(brand + separator + status))
        own_width = min(get_cwidth(self.own_name), available // 2)
        peer_width = min(get_cwidth(self.peer_name), available - own_width)
        own_width = min(get_cwidth(self.own_name), available - peer_width)
        own = _fit_label(self.own_name, max(1, own_width))
        peer = _fit_label(self.peer_name, max(1, peer_width))
        return [('class:brand', brand), ('class:peer', own + separator + peer),
                (state_style, status)]

    def _session_line(self):
        return f'  Session {self.session_id[:8]}    AES-256-GCM'

    def _counts_line(self):
        return f'  Sent {self.sent_count}    Received {self.received_count}'

    def _footer(self):
        if self._feedback:
            return '  ' + self._feedback
        if not self.connected:
            return '  /quit to close    PgUp/PgDn scroll    Ctrl+End latest'
        return '  Enter send    /clear    /quit    PgUp/PgDn scroll    Ctrl+End latest'

    def _dispatch(self, callback):
        with self._lock:
            if self._running and threading.get_ident() != self._owner_thread:
                try:
                    self._loop.call_soon_threadsafe(self._apply, callback)
                    return
                except RuntimeError:
                    # A receiver can report disconnect just as run() closes
                    # its event loop. Rendering has ended; retain state safely.
                    if not self._loop.is_closed():
                        raise
            self._apply(callback)

    def _apply(self, callback):
        with self._lock:
            callback()
            self.app.invalidate()

    def _render_transcript(self):
        lines = []
        for entry in self._entries:
            prefix = [('class:timestamp', f'  {entry.timestamp}  ')]
            if entry.outgoing is None:
                lines.append(prefix + [('class:notice', entry.text)])
            else:
                style = 'class:outgoing' if entry.outgoing else 'class:incoming'
                name = 'You' if entry.outgoing else entry.sender
                lines.append(prefix + [(style, name + '  '), ('class:message', entry.text)])
            lines.append([('', '')])
        self._formatted_lines = lines
        text = '\n'.join(''.join(fragment[1] for fragment in line) for line in lines)
        cursor = len(text) if self._follow_tail else min(self.transcript.buffer.cursor_position, len(text))
        self.transcript.buffer.set_document(Document(text, cursor), bypass_readonly=True)

    def _append_notice(self, text):
        self._entries.append(_Entry(datetime.now().strftime('%H:%M'), '', _display(text), None))
        self._render_transcript()

    def _append_message(self, sender, text, outgoing):
        self._entries.append(_Entry(datetime.now().strftime('%H:%M'), _display(sender),
                                    _display(text), bool(outgoing)))
        if outgoing:
            self.sent_count += 1
        else:
            self.received_count += 1
        self._render_transcript()

    def message(self, sender, text, outgoing=False):
        self._dispatch(lambda: self._append_message(sender, text, outgoing))

    def notice(self, text):
        self._dispatch(lambda: self._append_notice(text))

    def set_disconnected(self):
        def update():
            if self.connected:
                self.connected = False
                self._feedback = ''
                self._append_notice('Connection closed. /quit to exit.')
        self._dispatch(update)

    def _scroll(self, direction):
        document = self.transcript.buffer.document
        info = self.transcript.window.render_info
        distance = max(1, info.window_height - 2) if info else 10
        row = min(max(0, document.cursor_position_row + direction * distance), document.line_count - 1)
        self.transcript.buffer.cursor_position = document.translate_row_col_to_index(row, 0)
        self._follow_tail = direction > 0 and row == document.line_count - 1

    def _submit(self):
        text = self.composer.text
        command = text.strip()
        if command == '/quit':
            self._request_quit()
            return
        if command == '/clear':
            self._entries.clear()
            self._follow_tail = True
            self._feedback = ''
            self._render_transcript()
            self.composer.buffer.set_document(Document('', 0))
            return
        if not self.connected:
            self._feedback = 'Offline. Your draft has been kept. /quit to close.'
            return
        try:
            sent = self.on_send(text)
        except (OSError, ValueError) as error:
            self._append_notice(str(error))
            sent = False
        if sent:
            self._follow_tail = True
            self._append_message(self.own_name, text, True)
            self.composer.buffer.set_document(Document('', 0))
            self._feedback = ''
        else:
            self._feedback = 'Not sent. Edit your message and press Enter.'

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
