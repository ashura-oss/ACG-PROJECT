"""Exercise the actual fullscreen UI and encrypted receiver together."""
import socket
import threading
import time
import unittest
from unittest.mock import patch

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from chat import run_interactive_chat
from chat_protocol import (FrameReader, RecordReceiver, create_session,
                           encode_frame, encrypt_record)
from terminal_ui import TerminalChatUI


class InteractiveChatIntegrationTests(unittest.TestCase):
    def test_composer_and_encrypted_socket_receiver_share_live_ui(self):
        header, master = create_session('Alice', 'Bob')
        alice, bob = socket.socketpair()
        alice.settimeout(5)
        bob.settimeout(5)
        alice_reader, bob_reader = FrameReader(alice), FrameReader(bob)
        peer_observations, failures, instances = [], [], []
        next_reply = threading.Event()

        def wait_for(condition):
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if condition():
                    return
                time.sleep(0.01)
            self.fail('Interactive socket/UI event timed out')

        def peer():
            try:
                receiver = RecordReceiver(header, master, 'a_to_b')
                peer_observations.append(receiver.accept(bob_reader.read()))
                bob.sendall(encode_frame(encrypt_record(header, master, 'b_to_a', 0, 'Hello Alice')))
                if not next_reply.wait(timeout=4):
                    raise AssertionError('Draft was not ready for the second reply')
                bob.sendall(encode_frame(encrypt_record(header, master, 'b_to_a', 1, 'Still there?')))
                peer_observations.append(bob_reader.read())
            except BaseException as error:
                failures.append(error)

        with create_pipe_input() as keyboard:
            def make_ui(*arguments, **kwargs):
                ui = TerminalChatUI(*arguments, **kwargs, input=keyboard, output=DummyOutput())
                instances.append(ui)
                return ui

            def run():
                try:
                    run_interactive_chat(alice, alice_reader, header, master, 'alice')
                except BaseException as error:
                    failures.append(error)

            network_thread = threading.Thread(target=peer, daemon=True)
            ui_thread = threading.Thread(target=run, daemon=True)
            try:
                with patch('terminal_ui.TerminalChatUI', side_effect=make_ui):
                    network_thread.start()
                    ui_thread.start()
                    wait_for(lambda: instances and instances[0]._running)
                    ui = instances[0]
                    keyboard.send_text('Hello Bob\r')
                    wait_for(lambda: ui.received_count == 1 and ui.sent_count == 1)
                    self.assertEqual(peer_observations, ['Hello Bob'])
                    keyboard.send_text('A half-typed reply')
                    wait_for(lambda: ui.composer.text == 'A half-typed reply')
                    next_reply.set()
                    wait_for(lambda: ui.received_count == 2)
                    self.assertEqual(ui.composer.text, 'A half-typed reply')
                    self.assertIn('Still there?', ui.transcript.text)
                    keyboard.send_text('\x15/quit\r')
                    ui_thread.join(timeout=4)
                    network_thread.join(timeout=4)
                    self.assertFalse(ui_thread.is_alive())
                    self.assertFalse(network_thread.is_alive())
                    self.assertEqual(peer_observations, ['Hello Bob', None])
                    self.assertEqual(failures, [])
            finally:
                next_reply.set()
                if instances:
                    instances[0].stop()
                for connection in (alice, bob):
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                ui_thread.join(timeout=2)
                network_thread.join(timeout=2)
                alice_reader.close()
                bob_reader.close()
                alice.close()
                bob.close()


if __name__ == '__main__':
    unittest.main()
