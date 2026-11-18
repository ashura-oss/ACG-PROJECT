"""Post-quantum hybrid profile: X25519 + ML-KEM-768 key exchange."""
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import chat
from chat_protocol import (AuthenticationFailure, FrameReader, ProtocolError, create_hybrid_session,
                           decrypt_record, encrypt_record, generate_hybrid_key, hybrid_public,
                           is_hybrid, recover_hybrid_master, recover_master, validate_header)
from intercept import CaptureQueue


class HybridProtocolTests(unittest.TestCase):
    def setUp(self):
        self.key = generate_hybrid_key()
        self.header, self.master = create_hybrid_session('Alice', 'Bob', hybrid_public(self.key))

    def test_both_sides_derive_the_same_secret(self):
        self.assertTrue(is_hybrid(self.header))
        self.assertNotIn('N', self.header)
        self.assertEqual(len(bytes.fromhex(self.header['mlkem_ciphertext_hex'])), 1088)
        self.assertEqual(len(bytes.fromhex(self.header['x25519_ephemeral_hex'])), 32)
        self.assertEqual(recover_hybrid_master(self.header, self.key), self.master)

    def test_messages_round_trip_in_both_directions(self):
        master = recover_hybrid_master(self.header, self.key)
        for direction, text in (('a_to_b', 'hello Bob'), ('b_to_a', 'hello Alice')):
            frame = encrypt_record(self.header, self.master, direction, 0, text)
            self.assertEqual(decrypt_record(self.header, master, frame), text)

    def test_each_session_has_a_fresh_secret(self):
        _, other = create_hybrid_session('Alice', 'Bob', hybrid_public(self.key))
        self.assertNotEqual(other, self.master)

    def test_another_receiver_key_cannot_recover_the_secret(self):
        with self.assertRaises(ProtocolError):
            recover_hybrid_master(self.header, generate_hybrid_key())

    def test_tampered_ciphertext_changes_the_secret(self):
        tampered = dict(self.header)
        ciphertext = bytearray.fromhex(tampered['mlkem_ciphertext_hex'])
        ciphertext[0] ^= 1
        tampered['mlkem_ciphertext_hex'] = ciphertext.hex()
        frame = encrypt_record(self.header, self.master, 'a_to_b', 0, 'secret')
        wrong = recover_hybrid_master(tampered, self.key)
        self.assertNotEqual(wrong, self.master)
        with self.assertRaises(AuthenticationFailure):
            decrypt_record(self.header, wrong, frame)

    def test_header_validation_rejects_bad_fields(self):
        for field, value in (('mlkem_ciphertext_hex', 'ab'), ('x25519_ephemeral_hex', 'zz' * 32),
                             ('key_encoding', 'RSA-OAEP-SHA256')):
            with self.assertRaises(ProtocolError):
                validate_header({**self.header, field: value})
        with self.assertRaises(ProtocolError):
            validate_header({**self.header, 'N': 33})

    def test_rsa_recovery_path_refuses_hybrid_sessions(self):
        with self.assertRaises(ProtocolError):
            recover_master(self.header, 7)


class HybridHandshakeTests(unittest.TestCase):
    def test_real_socket_handshake(self):
        key = generate_hybrid_key()
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        result = {}

        def serve():
            connection, _ = listener.accept()
            with connection:
                reader = FrameReader(connection)
                try:
                    result['server'] = chat.hybrid_server_handshake(connection, reader, 'Bob', key)
                finally:
                    reader.close()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with socket.create_connection(listener.getsockname(), timeout=5) as connection:
                reader = FrameReader(connection)
                try:
                    header, master = chat.client_handshake(connection, reader, 'Alice')
                finally:
                    reader.close()
        finally:
            thread.join(timeout=5)
            listener.close()
        self.assertEqual(result['server'], (header, master))
        self.assertEqual(chat.key_label(header), 'X25519 + ML-KEM-768')

    def test_setup_writes_a_loadable_hybrid_key(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'pqc.json'
            chat.setup_key(path, pqc=True)
            self.assertEqual(chat.load_key(path)['kem'], 'X25519MLKEM768')


class HybridInterceptorTests(unittest.TestCase):
    def test_interceptor_cannot_recover_a_hybrid_session(self):
        key = generate_hybrid_key()
        header, master = create_hybrid_session('Alice', 'Bob', hybrid_public(key))
        frames = [('a_to_b', {'type': 'session', 'header': header}),
                  ('a_to_b', encrypt_record(header, master, 'a_to_b', 0, 'top secret')),
                  ('b_to_a', encrypt_record(header, master, 'b_to_a', 0, 'still secret'))]
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / 'chat.jsonl'
            with capture.open('w', encoding='utf-8') as stream:
                for index, (direction, frame) in enumerate(frames):
                    stream.write(json.dumps({'event': 'frame', 'connection_id': 'c1', 'direction': direction,
                                             'time_ns': index, 'frame': frame}) + '\n')
            lines = []
            queue = CaptureQueue(capture, seed=1, output=lines.append)
            self.assertEqual(queue.decrypt_all(), [])
            self.assertEqual(queue.recover(), 0)
            status = queue.status()[0]
        self.assertEqual(status['state'], 'QUANTUM_SAFE')
        self.assertEqual((status['captured'], status['pending'], status['decrypted']), (2, 2, 0))
        self.assertEqual(queue.transcript, [])
        output = '\n'.join(lines)
        self.assertIn('ML-KEM-768', output)
        self.assertEqual(output.count('Messages stay encrypted'), 1)
        self.assertNotIn('Running Shor', output)
        self.assertNotIn('top secret', output)


if __name__ == '__main__':
    unittest.main()
