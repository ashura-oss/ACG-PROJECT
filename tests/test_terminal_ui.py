"""Headless terminal interactions using the real prompt_toolkit event loop."""
import threading
import time
import unittest

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.utils import get_cwidth

from terminal_ui import TerminalChatUI


class TerminalUITests(unittest.TestCase):
    def start_ui(self, on_send=None):
        pipe_context = create_pipe_input()
        pipe = pipe_context.__enter__()
        self.addCleanup(pipe_context.__exit__, None, None, None)
        quit_calls = []
        sent = []
        ui = TerminalChatUI('Alice', 'Bob', 'a' * 32,
                            on_send or (lambda text: sent.append(text) or True),
                            lambda: quit_calls.append(True),
                            input=pipe, output=DummyOutput())
        errors = []
        def run():
            try:
                ui.run()
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        def stop():
            ui.stop()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive(), 'Terminal UI did not stop')
            self.assertEqual(errors, [])
        self.addCleanup(stop)
        self.wait_for(lambda: ui._running)
        return ui, pipe, sent, quit_calls, thread

    def wait_for(self, condition, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.01)
        self.fail('Timed out waiting for a terminal UI event')

    def test_incoming_preserves_unicode_draft_and_cursor(self):
        ui, pipe, sent, quit_calls, thread = self.start_ui()
        pipe.send_text('Draft 🔐 still typing')
        self.wait_for(lambda: ui.composer.text == 'Draft 🔐 still typing')
        # The receiver runs outside the UI event loop, as it does in chat.py.
        ui.message('Bob', 'Incoming message 🔐')
        self.wait_for(lambda: ui.received_count == 1)
        self.assertEqual(ui.composer.text, 'Draft 🔐 still typing')
        self.assertEqual(ui.composer.buffer.cursor_position, len('Draft 🔐 still typing'))
        self.assertIn('Incoming message 🔐', ui.transcript.text)
        self.assertEqual(sent, [])
        pipe.send_text('\r')
        self.wait_for(lambda: ui.sent_count == 1)
        self.assertEqual(sent, ['Draft 🔐 still typing'])
        self.assertEqual(ui.composer.text, '')

    def test_invalid_send_keeps_draft_then_allows_edit_and_resend(self):
        attempts = []
        def send(text):
            attempts.append(text)
            return len(text.encode('utf-8')) <= 4096
        ui, pipe, _, quit_calls, thread = self.start_ui(send)
        draft = 'x' * 4097
        pipe.send_text(draft + '\r')
        self.wait_for(lambda: len(attempts) == 1)
        self.assertEqual(ui.composer.text, draft)
        self.assertEqual(ui.sent_count, 0)
        pipe.send_text('\x7f\r')
        self.wait_for(lambda: ui.sent_count == 1)
        self.assertEqual(attempts[-1], 'x' * 4096)
        self.assertEqual(ui.composer.text, '')

    def test_clear_changes_view_only_and_preserves_transport_counts(self):
        ui, pipe, sent, quit_calls, thread = self.start_ui()
        pipe.send_text('first message\r')
        self.wait_for(lambda: ui.sent_count == 1)
        ui.message('Bob', 'first reply')
        self.wait_for(lambda: ui.received_count == 1)
        pipe.send_text('/clear\r')
        self.wait_for(lambda: ui.transcript.text == '')
        self.assertEqual((ui.sent_count, ui.received_count), (1, 1))
        self.assertEqual(sent, ['first message'])
        self.assertEqual(quit_calls, [])
        pipe.send_text('second message\r')
        self.wait_for(lambda: ui.sent_count == 2)
        self.assertEqual(sent, ['first message', 'second message'])

    def test_remote_disconnect_retains_view_and_draft_until_quit(self):
        ui, pipe, sent, quit_calls, thread = self.start_ui()
        ui.message('Bob', 'Keep this conversation')
        pipe.send_text('unsent draft')
        self.wait_for(lambda: ui.composer.text == 'unsent draft')
        ui.set_disconnected()
        self.wait_for(lambda: not ui.connected)
        self.assertTrue(thread.is_alive())
        self.assertIn('Keep this conversation', ui.transcript.text)
        pipe.send_text('\r')
        self.wait_for(lambda: 'Offline' in ui._feedback)
        self.assertEqual(ui.composer.text, 'unsent draft')
        self.assertEqual(sent, [])
        pipe.send_text('\x15/quit\r')
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(quit_calls, [True])

    def test_control_c_quits_once_without_sending_draft(self):
        ui, pipe, sent, quit_calls, thread = self.start_ui()
        pipe.send_text('do not send\x03')
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(quit_calls, [True])
        self.assertEqual(sent, [])

    def test_scroll_keeps_compose_focus_and_incoming_draft(self):
        ui, pipe, sent, quit_calls, thread = self.start_ui()
        for index in range(40):
            ui.message('Bob', f'history message {index}')
        self.wait_for(lambda: ui.received_count == 40)
        pipe.send_text('working draft\x1b[5~')  # PageUp
        self.wait_for(lambda: not ui._follow_tail)
        self.assertEqual(ui.composer.text, 'working draft')
        self.assertTrue(ui.app.layout.has_focus(ui.composer))
        cursor = ui.transcript.buffer.cursor_position
        ui.message('Bob', 'new incoming while reading history')
        self.wait_for(lambda: ui.received_count == 41)
        self.assertEqual(ui.transcript.buffer.cursor_position, cursor)
        self.assertEqual(ui.composer.text, 'working draft')
        pipe.send_text('\r')
        self.wait_for(lambda: ui.sent_count == 1)
        self.assertTrue(ui._follow_tail)
        self.assertEqual(ui.transcript.buffer.cursor_position, len(ui.transcript.text))

    def test_header_keeps_connection_state_visible_with_wide_unicode_names(self):
        with create_pipe_input() as pipe:
            ui = TerminalChatUI('愛' * 32, '長' * 32, 'a' * 32, lambda _: True,
                                lambda: None, input=pipe, output=DummyOutput())
            header = ''.join(text for _, text in ui._header())
            self.assertLessEqual(get_cwidth(header), ui.app.output.get_size().columns)
            self.assertIn('CONNECTED', header)
            self.assertIn('…', header)

    def test_stop_before_run_returns_without_starting_application(self):
        with create_pipe_input() as pipe:
            ui = TerminalChatUI('Alice', 'Bob', 'a' * 32, lambda _: True,
                                lambda: None, input=pipe, output=DummyOutput())
            ui.stop()
            ui.run()
            self.assertFalse(ui._running)


if __name__ == '__main__':
    unittest.main()
