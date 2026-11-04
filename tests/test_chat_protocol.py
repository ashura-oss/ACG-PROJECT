import copy
import socket
import threading
import unittest

from chat import client_handshake, server_handshake
from chat_protocol import (AuthenticationFailure, FrameReader, MAX_FRAME_BYTES,
                           ProtocolError, RecordReceiver, create_session,
                           decode_frame, decrypt_record, derive_keys,
                           encode_frame, encrypt_record, recover_master,
                           validate_header)


class ChatProtocolTests(unittest.TestCase):
    def setUp(self):
        self.header, self.master = create_session('Alice', 'Bob')

    def test_bidirectional_keys_and_full_message_limits(self):
        keys = derive_keys(self.master, self.header)
        self.assertNotEqual(keys['a_to_b'], keys['b_to_a'])
        self.assertEqual(recover_master(self.header, 7), self.master)
        for direction in ('a_to_b', 'b_to_a'):
            receiver = RecordReceiver(self.header, self.master, direction)
            for sequence, text in enumerate(('', 'Hello 🔐', 'a' * 4096, '🔐' * 1024)):
                frame = encrypt_record(self.header, self.master, direction, sequence, text)
                wire = encode_frame(frame)
                self.assertLessEqual(len(wire), MAX_FRAME_BYTES)
                self.assertEqual(receiver.accept(decode_frame(wire)), text)
        for text in ('a' * 4097, '🔐' * 1025, 'two\nlines', '\x1b[31m'):
            with self.assertRaises(ProtocolError):
                encrypt_record(self.header, self.master, 'a_to_b', 0, text)

    def test_tampering_never_advances_receiver(self):
        frame = encrypt_record(self.header, self.master, 'a_to_b', 0, 'secret')
        receiver = RecordReceiver(self.header, self.master, 'a_to_b')
        damaged = copy.deepcopy(frame)
        damaged['ciphertext_and_tag_hex'] = ('0' if frame['ciphertext_and_tag_hex'][0] != '0' else '1') + frame['ciphertext_and_tag_hex'][1:]
        with self.assertRaises(AuthenticationFailure):
            receiver.accept(damaged)
        self.assertEqual(receiver.next_sequence, 0)
        self.assertEqual(receiver.accept(frame), 'secret')
        with self.assertRaisesRegex(ProtocolError, 'sequence'):
            receiver.accept(frame)

    def test_direction_header_and_session_are_authenticated(self):
        frame = encrypt_record(self.header, self.master, 'a_to_b', 0, 'secret')
        changed_direction = {**frame, 'direction': 'b_to_a'}
        with self.assertRaises(AuthenticationFailure):
            decrypt_record(self.header, self.master, changed_direction)
        changed_header = {**self.header, 'alice': 'Mallory'}
        with self.assertRaises(AuthenticationFailure):
            decrypt_record(changed_header, self.master, frame)
        changed_session = {**frame, 'session_id': 'f' * 32}
        with self.assertRaisesRegex(ProtocolError, 'another session'):
            decrypt_record(self.header, self.master, changed_session)
        changed_sequence = {**frame, 'sequence': 1}
        with self.assertRaises(AuthenticationFailure):
            decrypt_record(self.header, self.master, changed_sequence)
        for sequence in (True, -1, 2**64):
            with self.assertRaises(ProtocolError):
                encrypt_record(self.header, self.master, 'a_to_b', sequence, 'x')

    def test_header_schema_is_strict(self):
        for field, value in (('version', True), ('N', 33.0), ('e', 5),
                             ('alice', '\x1b[2J'), ('session_id', 'x' * 32),
                             ('wrapped_key_digits', [True] * 64)):
            with self.assertRaises(ProtocolError):
                validate_header({**self.header, field: value})
        with self.assertRaises(ProtocolError):
            validate_header({**self.header, 'secret_key': self.master.hex()})

    def test_framing_rejects_duplicates_oversize_and_partial_eof(self):
        for wire in (b'{"type":"x","type":"y"}\n', b'{}', b'[]\n',
                     b'{"x":NaN}\n', b'{' + b' ' * MAX_FRAME_BYTES + b'}\n'):
            with self.assertRaises(ProtocolError):
                decode_frame(wire)
        first, second = socket.socketpair()
        with first, second:
            reader = FrameReader(first)
            try:
                second.sendall(b'{"type":"first"}\n{"type":"second"}\n{"unfinished":')
                second.shutdown(socket.SHUT_WR)
                self.assertEqual(reader.read()['type'], 'first')
                self.assertEqual(reader.read()['type'], 'second')
                with self.assertRaisesRegex(ProtocolError, 'Incomplete'):
                    reader.read()
            finally:
                reader.close()

    def test_actual_socket_handshake_and_two_way_records(self):
        alice, bob = socket.socketpair()
        errors = []
        observations = []

        def bob_side():
            with bob:
                bob.settimeout(5)
                reader = FrameReader(bob)
                try:
                    header, master = server_handshake(bob, reader, 'Bob', 7)
                    observations.append(RecordReceiver(header, master, 'a_to_b').accept(reader.read()))
                    bob.sendall(encode_frame(encrypt_record(header, master, 'b_to_a', 0, 'reply')))
                except Exception as error:
                    errors.append(error)
                finally:
                    reader.close()

        thread = threading.Thread(target=bob_side)
        thread.start()
        with alice:
            alice.settimeout(5)
            reader = FrameReader(alice)
            try:
                header, master = client_handshake(alice, reader, 'Alice')
                alice.sendall(encode_frame(encrypt_record(header, master, 'a_to_b', 0, 'hello')))
                self.assertEqual(RecordReceiver(header, master, 'b_to_a').accept(reader.read()), 'reply')
            finally:
                reader.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(observations, ['hello'])


if __name__ == '__main__':
    unittest.main()
