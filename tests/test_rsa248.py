"""248-bit exchange, framing, timing boundaries and safe simulator rejection."""
import copy
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from chat import client_handshake, server_handshake
from chat_protocol import (AuthenticationFailure, FrameReader, ProtocolError,
                           RecordReceiver, create_session, decrypt_record,
                           encode_frame, encrypt_record, recover_master,
                           validate_header)
from intercept import CaptureQueue
from rsa_modes import generate_key, simulator_resources, validate_private
from shor import AttackFailure, build_circuit, controlled_multiplier, run_factorization


class RSA248Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_key(248)

    def test_key_has_exact_requested_bits_and_valid_private_exponent(self):
        self.assertEqual(self.key['N'].bit_length(), 248)
        self.assertEqual(self.key['e'], 65537)
        self.assertEqual(validate_private(self.key), self.key)
        with self.assertRaises(ValueError):
            validate_private({**self.key, 'd': 3})
        self.assertNotEqual(generate_key(248)['N'], self.key['N'])

    def session(self):
        return create_session('Alice', 'Bob', public_key=(self.key['N'], self.key['e']))

    def test_seed_wrapping_and_authenticated_bidirectional_messages(self):
        header, master = self.session()
        self.assertEqual(header['version'], 2)
        self.assertEqual(len(header['wrapped_seed_hex']), 62)
        self.assertNotIn('wrapped_key_digits', header)
        recovered = recover_master(header, self.key['d'])
        self.assertEqual(master, recovered)
        for direction in ('a_to_b', 'b_to_a'):
            receiver = RecordReceiver(header, recovered, direction)
            for sequence, message in enumerate(('', 'Hello 🔐', 'x' * 4096)):
                self.assertEqual(receiver.accept(encrypt_record(header, master, direction, sequence, message)), message)
        with self.assertRaises(ProtocolError):
            recover_master(header, 3)

    def test_v2_schema_and_header_authentication_reject_tampering(self):
        header, master = self.session()
        for field, value in (('version', True), ('N', 248), ('e', 3),
                             ('wrapped_seed_hex', 'f' * 62), ('wrapped_seed_hex', '00')):
            with self.assertRaises(ProtocolError):
                validate_header({**header, field: value})
        record = encrypt_record(header, master, 'a_to_b', 0, 'secret')
        changed = copy.deepcopy(header)
        changed['alice'] = 'Mallory'
        with self.assertRaises(AuthenticationFailure):
            decrypt_record(changed, master, record)

    def test_real_socket_handshake_uses_248_bit_public_key(self):
        alice, bob = socket.socketpair()
        observed, errors = [], []
        def peer():
            reader = FrameReader(bob)
            try:
                header, master = server_handshake(bob, reader, 'Bob', self.key['d'],
                                                   public_key=(self.key['N'], self.key['e']))
                observed.append(header['N'].bit_length())
                observed.append(RecordReceiver(header, master, 'a_to_b').accept(reader.read()))
                bob.sendall(encode_frame(encrypt_record(header, master, 'b_to_a', 0, '248 reply')))
            except Exception as error:
                errors.append(error)
            finally:
                reader.close()
                bob.close()
        for connection in (alice, bob):
            connection.settimeout(5)
        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        with alice:
            reader = FrameReader(alice)
            try:
                header, master = client_handshake(alice, reader, 'Alice')
                self.assertEqual(header['N'], self.key['N'])
                alice.sendall(encode_frame(encrypt_record(header, master, 'a_to_b', 0, '248 message')))
                self.assertEqual(RecordReceiver(header, master, 'b_to_a').accept(reader.read()), '248 reply')
            finally:
                reader.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(observed, [248, '248 message'])

    def test_large_simulator_requests_reject_before_process_or_matrix_allocation(self):
        resources = simulator_resources(self.key['N'])
        self.assertEqual(resources['total_qubits'], 744)
        self.assertEqual(resources['statevector_bytes'], 1 << 748)
        self.assertEqual(resources['controlled_matrix_bytes'], 1 << 502)
        with patch('shor.mp.get_context', side_effect=AssertionError('Must not spawn an infeasible simulator')):
            with self.assertRaisesRegex(AttackFailure, 'capacity'):
                run_factorization(modulus=self.key['N'])
        with self.assertRaises(AttackFailure):
            build_circuit(modulus=self.key['N'])
        with self.assertRaises(AttackFailure):
            controlled_multiplier(5, modulus=self.key['N'])

    def test_interceptor_keeps_248_bit_messages_queued_without_fabricated_key(self):
        header, master = self.session()
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / 'capture.jsonl'
            frames = [{'type': 'session', 'header': header},
                      encrypt_record(header, master, 'a_to_b', 0, 'NOT RECOVERED')]
            with capture.open('w', encoding='utf-8') as stream:
                for frame in frames:
                    stream.write(json.dumps({'event': 'frame', 'connection_id': 'rsa248',
                                             'direction': 'a_to_b', 'time_ns': 1, 'frame': frame}) + '\n')
            output = []
            queue = CaptureQueue(capture, output=output.append)
            self.assertEqual(queue.decrypt_all(), [])
            self.assertEqual(queue.status()[0]['pending'], 1)
            self.assertFalse(queue.private_exponents)
            self.assertFalse(queue.evidence)
            self.assertFalse(queue.transcript)
            self.assertIsNone(queue.sessions[header['session_id']].master)
            self.assertIn('capacity', '\n'.join(output))
            self.assertNotIn('NOT RECOVERED', '\n'.join(output))


if __name__ == '__main__':
    unittest.main()
