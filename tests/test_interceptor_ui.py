"""Real headless dashboard event-loop interactions, without a capture driver."""
import threading
import time
import unittest

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.data_structures import Size

from interceptor_ui import InterceptorUI


def snapshot(**overrides):
    value = {'capture_state': 'LIVE', 'capture_name': 'capture.jsonl',
             'interface': 'loopback', 'port': 9001, 'busy': None, 'follow': False,
             'sessions': [], 'transcript': [], 'traffic': [], 'evidence': [], 'errors': 0}
    value.update(overrides)
    return value


class InterceptorUITests(unittest.TestCase):
    def wait_for(self, condition, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.01)
        self.fail('Timed out waiting for dashboard input')

    def start_ui(self, accepted=True):
        context = create_pipe_input()
        pipe = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        commands, quits, errors = [], [], []
        def command(value):
            commands.append(value)
            return accepted
        ui = InterceptorUI(command, lambda: quits.append(True), input=pipe, output=DummyOutput())
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
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
        self.addCleanup(stop)
        self.wait_for(lambda: ui._running)
        return ui, pipe, commands, quits, thread

    def test_snapshot_and_logs_preserve_typed_unicode_command(self):
        ui, pipe, commands, quits, thread = self.start_ui()
        pipe.send_text('export "conversation 🔐.jsonl"')
        self.wait_for(lambda: ui.composer.text.endswith('.jsonl"'))
        draft = ui.composer.text
        ui.update(snapshot(busy='Recovering RSA key'))
        ui.log('Circuit running')
        self.wait_for(lambda: ui.snapshot.get('busy') == 'Recovering RSA key')
        self.wait_for(lambda: 'Circuit running' in ui.activity_view.text)
        self.assertEqual(ui.composer.text, draft)
        self.assertEqual(ui.composer.buffer.cursor_position, len(draft))
        self.assertEqual(commands, [])
        pipe.send_text('\r')
        self.wait_for(lambda: len(commands) == 1)
        self.assertEqual(commands, [draft])
        self.assertEqual(ui.composer.text, '')

    def test_function_keys_preserve_draft_and_toggle_follow(self):
        ui, pipe, commands, quits, thread = self.start_ui()
        ui.update(snapshot())
        pipe.send_text('unfinished command\x1bOQ\x1bOR\x1bOS')
        self.wait_for(lambda: len(commands) == 3)
        self.assertEqual(commands, ['recover', 'decrypt-all', 'follow'])
        self.assertEqual(ui.composer.text, 'unfinished command')
        ui.update(snapshot(follow=True))
        self.wait_for(lambda: ui.snapshot.get('follow'))
        pipe.send_text('\x1bOS')
        self.wait_for(lambda: len(commands) == 4)
        self.assertEqual(commands[-1], 'unfollow')
        self.assertEqual(ui.composer.text, 'unfinished command')

    def test_invalid_command_retains_input(self):
        ui, pipe, commands, quits, thread = self.start_ui(accepted=False)
        pipe.send_text('invalid command\r')
        self.wait_for(lambda: len(commands) == 1)
        self.assertEqual(ui.composer.text, 'invalid command')
        self.assertIn('not accepted', ui._footer())

    def test_queued_or_rejected_traffic_never_uses_untrusted_plaintext(self):
        ui, pipe, commands, quits, thread = self.start_ui()
        ui.update(snapshot(capture_state='ERROR', errors=2, sessions=[
            {'session_id': 'a' * 32, 'alice': 'Alice', 'bob': 'Bob', 'captured': 2,
             'pending': 1, 'decrypted': 0, 'errors': 1, 'state': 'INCOMPLETE_OR_INVALID'}],
            traffic=[{'session_id': 'a' * 32, 'direction': 'a_to_b', 'sequence': 0,
                      'ciphertext_preview': 'ab12cd34', 'text': 'DO_NOT_RENDER_QUEUED', 'processed': False},
                     {'session_id': 'a' * 32, 'direction': 'a_to_b', 'sequence': 1,
                      'ciphertext_preview': 'ffab', 'text': 'DO_NOT_RENDER_REJECTED',
                      'error': 'Authentication failed', 'processed': True}],
            transcript=[{'session_id': 'a' * 32, 'direction': 'a_to_b', 'sequence': 2,
                         'sender': 'Alice', 'receiver': 'Bob', 'text': 'DO_NOT_RENDER_INVALID',
                         'authenticated': False}]))
        self.wait_for(lambda: ui.snapshot.get('capture_state') == 'ERROR')
        self.assertIn('QUEUED', ui.traffic_view.text)
        self.assertIn('ab12cd34', ui.traffic_view.text)
        self.assertIn('REJECTED', ui.traffic_view.text)
        self.assertIn('INCOMPLETE', ui.session_view.text)
        self.assertNotIn('DO_NOT_RENDER', ui.traffic_view.text)

    def test_authenticated_transcript_and_quantum_evidence_are_visible(self):
        ui, pipe, commands, quits, thread = self.start_ui()
        ui.update(snapshot(transcript=[{'session_id': 'a' * 32, 'direction': 'a_to_b',
                                       'sequence': 0, 'sender': 'Alice', 'receiver': 'Bob',
                                       'text': 'Authenticated conversation 🔐'}],
                           evidence=[{'N': 33, 'order': 10, 'factors': [3, 11], 'shots': 1024,
                                      'sample': '011001100110', 'phase': 0.3999,
                                      'convergent': [2, 5], 'elapsed_seconds': 4.5,
                                      'counts': {'011001100110': 140, '000000000000': 100}}]))
        self.wait_for(lambda: 'Authenticated conversation 🔐' in ui.traffic_view.text)
        self.assertIn('DECRYPTED', ui.traffic_view.text)
        self.assertIn('order 10', ui.quantum_view.text)
        self.assertIn('factors 3 × 11', ui.quantum_view.text)
        self.assertIn('1,024 shots', ui.quantum_view.text)
        self.assertIn('011001100110', ui.quantum_view.text)

    def test_activity_is_bounded_and_clear_keeps_capture_state(self):
        ui, pipe, commands, quits, thread = self.start_ui()
        ui.update(snapshot(follow=True))
        for index in range(230):
            ui.log(f'event {index}')
        self.wait_for(lambda: 'event 229' in ui.activity_view.text)
        self.assertEqual(len(ui.activity_log), 200)
        self.assertNotIn('event 0\n', ui.activity_view.text)
        ui.clear_log()
        self.wait_for(lambda: len(ui.activity_log) == 0)
        self.assertTrue(ui.snapshot['follow'])

    def test_control_c_quits_exactly_once(self):
        ui, pipe, commands, quits, thread = self.start_ui()
        pipe.send_text('unsent\x03')
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(quits, [True])
        self.assertEqual(commands, [])

    def test_compact_and_wide_layouts_render_dashboard_and_command_bar(self):
        for columns, rows in ((80, 24), (120, 36)):
            class Output(DummyOutput):
                def get_size(self): return Size(rows=rows, columns=columns)
            with create_pipe_input() as keyboard:
                ui = InterceptorUI(lambda _: True, lambda: None, input=keyboard, output=Output())
                ui.update(snapshot())
                rendered = []
                def capture_screen(app):
                    screen = app.renderer._last_screen
                    if rendered or screen is None:
                        return
                    rendered.append('\n'.join(''.join(screen.data_buffer[y][x].char
                                                      for x in range(columns))
                                              for y in range(rows)))
                    app.exit()
                ui.app.after_render += capture_screen
                ui.run()
                self.assertNotIn('Window too small', rendered[0])
                for label in ('INTERCEPTOR', 'SESSION QUEUE', 'TRAFFIC', 'QUANTUM EVIDENCE', 'Command', 'F3'):
                    self.assertIn(label, rendered[0])


if __name__ == '__main__':
    unittest.main()
