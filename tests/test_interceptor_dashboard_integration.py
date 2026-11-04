"""Dashboard/controller integration with real quantum recovery and UI input."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from chat_protocol import create_session, encrypt_record
from intercept import CaptureQueue
from interceptor_controller import InterceptorController
from interceptor_ui import InterceptorUI


class DashboardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.capture = Path(self.directory.name) / 'public-capture.jsonl'
        self.header, self.master = create_session('Alice', 'Bob')

    def append(self, frame, direction='a_to_b'):
        event = {'event': 'frame', 'connection_id': 'connection-one',
                 'direction': direction, 'time_ns': time.time_ns(), 'frame': frame}
        with self.capture.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(event) + '\n')

    def wait_for(self, condition, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.02)
        self.fail('Dashboard operation did not complete')

    def test_real_shor_follow_and_draft_preservation(self):
        self.append({'type': 'session', 'header': self.header})
        self.append(encrypt_record(self.header, self.master, 'a_to_b', 0, 'FIRST_AUTHENTICATED'))
        queue = CaptureQueue(self.capture, seed=42, output=lambda _: None)
        controller = InterceptorController(queue)
        errors = []
        with create_pipe_input() as keyboard:
            ui = InterceptorUI(controller.submit, lambda: (controller.close(wait=False), ui.stop()),
                               input=keyboard, output=DummyOutput())
            controller.attach_ui(ui)
            def run_ui():
                try:
                    ui.run()
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=run_ui, daemon=True)
            try:
                controller.start()
                thread.start()
                self.wait_for(lambda: ui._running and len(ui.snapshot.get('traffic', [])) == 1)
                self.assertNotIn('FIRST_AUTHENTICATED', ui.traffic_view.text)
                keyboard.send_text('unfinished export command')
                self.wait_for(lambda: ui.composer.text == 'unfinished export command')
                keyboard.send_text('\x1bOR')  # F3: actual Shor, not a factor fixture.
                self.wait_for(lambda: 'FIRST_AUTHENTICATED' in ui.traffic_view.text)
                self.assertEqual(ui.composer.text, 'unfinished export command')
                self.assertEqual(ui.snapshot['evidence'][0]['order'], 10)
                self.assertEqual(ui.snapshot['evidence'][0]['factors'], [3, 11])

                self.append(encrypt_record(self.header, self.master, 'b_to_a', 0, 'LIVE_REPLY'), 'b_to_a')
                self.wait_for(lambda: len(ui.snapshot['traffic']) == 2)
                self.assertNotIn('LIVE_REPLY', ui.traffic_view.text)
                keyboard.send_text('\x1bOS')  # F4 enables follow with the recovered key.
                self.wait_for(lambda: ui.snapshot.get('follow') and 'LIVE_REPLY' in ui.traffic_view.text)
                self.assertEqual(len(ui.snapshot['evidence']), 1)
                self.assertEqual(ui.composer.text, 'unfinished export command')

                valid = encrypt_record(self.header, self.master, 'a_to_b', 1, 'MUST_NOT_LEAK')
                damaged = copy.deepcopy(valid)
                ciphertext = damaged['ciphertext_and_tag_hex']
                damaged['ciphertext_and_tag_hex'] = ('0' if ciphertext[0] != '0' else '1') + ciphertext[1:]
                self.append(damaged)
                self.wait_for(lambda: any(row.get('error') for row in ui.snapshot['traffic']))
                self.assertNotIn('MUST_NOT_LEAK', ui.traffic_view.text)
                self.assertIn('REJECTED', ui.traffic_view.text)
                keyboard.send_text('\x03')
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
            finally:
                ui.stop()
                self.assertTrue(controller.close())
                thread.join(timeout=3)

    def test_controller_does_not_block_ui_submission_or_stop_attached_capture(self):
        self.append({'type': 'session', 'header': self.header})
        entered, release = threading.Event(), threading.Event()
        class Capture:
            stopped = False
            def poll(self): return None
            def terminate(self): self.stopped = True
        class View:
            def __init__(self): self.values, self.logs = [], []
            def update(self, value): self.values.append(value)
            def log(self, value): self.logs.append(value)
        process, view = Capture(), View()
        controller = InterceptorController(CaptureQueue(self.capture), process).attach_ui(view)
        def blocked_recovery(**kwargs):
            entered.set()
            release.wait(timeout=4)
            raise ValueError('Test quantum failure')
        with patch('intercept.run_factorization', side_effect=blocked_recovery):
            try:
                controller.start()
                controller.submit('recover')
                self.assertTrue(entered.wait(timeout=3))
                self.assertFalse(controller.submit('unknown-command'))
                started = time.monotonic()
                self.assertTrue(controller.submit('help'))
                self.assertLess(time.monotonic() - started, 0.2)
                self.assertEqual(controller.snapshot()['busy'], 'Recovering RSA key')
                release.set()
                self.wait_for(lambda: controller.snapshot().get('feedback') == 'Commands listed in activity')
                self.assertEqual(controller.snapshot()['sessions'][0]['pending'], 0)
                self.assertEqual(controller.snapshot()['transcript'], [])
            finally:
                release.set()
                self.assertTrue(controller.close())
        self.assertFalse(process.stopped)


if __name__ == '__main__':
    unittest.main()
