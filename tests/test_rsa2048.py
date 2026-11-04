"""Standard RSA-2048 OAEP exchange and the passive observer boundary."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from chat import client_handshake, load_key, server_handshake, setup_key
from chat_protocol import (AuthenticationFailure, FrameReader, ProtocolError,
                           RecordReceiver, create_session, decrypt_record,
                           encode_frame, encrypt_record, recover_master, validate_header)
from intercept import CaptureQueue
from rsa_modes import generate_key, simulator_resources, validate_private
from shor import AttackFailure, run_factorization


class RSA2048Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_key(2048)
        validate_private(cls.key)

    def session(self):
        return create_session('Alice', 'Bob', public_key=(self.key['N'], self.key['e']))

    def test_default_setup_writes_and_loads_exact_2048_bit_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.json'
            setup_key(path)
            key = load_key(path)
            self.assertEqual(key['N'].bit_length(), 2048)
            self.assertEqual(key['e'], 65537)
            self.assertGreater(path.stat().st_size, 1024)
            with self.assertRaises(FileExistsError):
                setup_key(path)

    def test_oaep_wraps_full_256_bit_master_and_both_directions_authenticate(self):
        header, master = self.session()
        self.assertEqual(header['version'], 3)
        self.assertEqual(header['key_encoding'], 'RSA-OAEP-SHA256')
        self.assertEqual(len(header['wrapped_key_hex']), 512)
        self.assertEqual(len(master), 32)
        recovered = recover_master(header, self.key['d'])
        self.assertEqual(master, recovered)
        for direction in ('a_to_b', 'b_to_a'):
            receiver = RecordReceiver(header, recovered, direction)
            for sequence, message in enumerate(('', 'RSA-2048 🔐', 'x' * 4096)):
                frame = encrypt_record(header, master, direction, sequence, message)
                self.assertEqual(receiver.accept(frame), message)

    def test_oaep_ciphertext_and_label_tampering_fail(self):
        header, master = self.session()
        changed = {**header, 'alice': 'Mallory'}
        with self.assertRaisesRegex(ProtocolError, 'unwrap failed'):
            recover_master(changed, self.key['d'])
        ciphertext = header['wrapped_key_hex']
        changed = {**header, 'wrapped_key_hex': ('0' if ciphertext[0] != '0' else '1') + ciphertext[1:]}
        with self.assertRaises(ProtocolError):
            recover_master(changed, self.key['d'])
        record = encrypt_record(header, master, 'a_to_b', 0, 'unchanged')
        with self.assertRaises(AuthenticationFailure):
            decrypt_record({**header, 'bob': 'Eve'}, master, record)
        for field, value in (('version', True), ('N', 2048), ('wrapped_key_hex', '00'), ('e', 3)):
            with self.assertRaises(ProtocolError):
                validate_header({**header, field: value})

    def test_real_socket_handshake_exchanges_encrypted_messages(self):
        alice, bob = socket.socketpair()
        alice.settimeout(5)
        bob.settimeout(5)
        observed, errors = [], []
        def peer():
            reader = FrameReader(bob)
            try:
                header, master = server_handshake(bob, reader, 'Bob', self.key['d'],
                                                   public_key=(self.key['N'], self.key['e']))
                observed.append(header['N'].bit_length())
                observed.append(RecordReceiver(header, master, 'a_to_b').accept(reader.read()))
                bob.sendall(encode_frame(encrypt_record(header, master, 'b_to_a', 0, '2048 reply')))
            except Exception as error:
                errors.append(error)
            finally:
                reader.close()
                bob.close()
        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        with alice:
            reader = FrameReader(alice)
            try:
                header, master = client_handshake(alice, reader, 'Alice')
                self.assertEqual(header['N'], self.key['N'])
                alice.sendall(encode_frame(encrypt_record(header, master, 'a_to_b', 0, '2048 message')))
                self.assertEqual(RecordReceiver(header, master, 'b_to_a').accept(reader.read()), '2048 reply')
            finally:
                reader.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(observed, [2048, '2048 message'])

    def test_simulator_rejects_2048_before_starting_a_worker(self):
        self.assertEqual(simulator_resources(self.key['N'])['total_qubits'], 6144)
        with patch('shor.mp.get_context', side_effect=AssertionError('Must not allocate simulator')):
            with self.assertRaisesRegex(AttackFailure, 'RSA-2048.*capacity'):
                run_factorization(modulus=self.key['N'])

    def test_observer_keeps_ciphertext_queued_and_does_not_recover_private_key(self):
        header, master = self.session()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.jsonl'
            frames = [{'type': 'session', 'header': header},
                      encrypt_record(header, master, 'a_to_b', 0, 'NO OBSERVER PLAINTEXT')]
            with path.open('w', encoding='utf-8') as stream:
                for frame in frames:
                    stream.write(json.dumps({'event': 'frame', 'connection_id': 'rsa2048',
                                             'direction': 'a_to_b', 'time_ns': 1, 'frame': frame}) + '\n')
            output = []
            observer = CaptureQueue(path, output=output.append)
            self.assertEqual(observer.decrypt_all(), [])
            self.assertEqual(observer.status()[0]['pending'], 1)
            self.assertFalse(observer.private_exponents)
            self.assertFalse(observer.transcript)
            self.assertIn('RSA-2048', '\n'.join(output))
            self.assertNotIn('NO OBSERVER PLAINTEXT', '\n'.join(output))


if __name__ == '__main__':
    unittest.main()
