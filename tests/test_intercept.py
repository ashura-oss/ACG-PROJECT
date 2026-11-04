"""Capture-queue boundaries; actual Shor execution is exercised by integration."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from chat_protocol import create_session, encrypt_record
from intercept import CaptureError, CaptureQueue, main
from shor import AttackFailure


def measured_fixture():
    # A unit-test fixture, not claimed to be a new simulator measurement.
    return {'factors': [3, 11], 'counts': {'011001100110': 1024},
            'sample': '011001100110', 'phase': 0.3999, 'convergent': [2, 5],
            'order': 10, 'shots': 1024, 'elapsed_seconds': 0.1}


class CaptureQueueTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.capture = self.directory / 'capture.jsonl'
        self.output = []
        self.queue = CaptureQueue(self.capture, seed=42, output=self.output.append)
        self.header, self.master = create_session('Alice', 'Bob')

    def event(self, frame, direction='a_to_b', connection='flow-1', timestamp=1):
        return {'event': 'frame', 'connection_id': connection,
                'direction': direction, 'time_ns': timestamp, 'frame': frame}

    def append(self, event):
        with self.capture.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(event, ensure_ascii=True) + '\n')

    def handshake(self, header=None, connection='flow-1'):
        self.append(self.event({'type': 'session', 'header': header or self.header},
                               connection=connection))

    def message(self, direction='a_to_b', sequence=0, text='secret',
                header=None, master=None, connection='flow-1'):
        frame = encrypt_record(header or self.header, master or self.master,
                               direction, sequence, text)
        self.append(self.event(frame, direction, connection))
        return frame

    def test_partial_append_waits_for_complete_line_without_duplication(self):
        self.assertEqual(self.queue.refresh(), 0)
        data = json.dumps(self.event({'type': 'session', 'header': self.header})).encode()
        self.capture.write_bytes(data[:20])
        self.assertEqual(self.queue.refresh(), 0)
        self.assertFalse(self.queue.sessions)
        self.assertTrue(self.queue.has_partial_line)
        with self.capture.open('ab') as stream:
            stream.write(data[20:] + b'\n')
        self.assertEqual(self.queue.refresh(), 1)
        self.assertEqual(len(self.queue.sessions), 1)
        self.assertFalse(self.queue.has_partial_line)
        self.assertEqual(self.queue.refresh(), 0)

    def test_two_directions_decrypt_once_and_export_without_secrets(self):
        self.handshake()
        self.message(text='Hello quantum 🔐')
        self.message('b_to_a', text='Reply')
        self.assertEqual(self.queue.status()[0]['state'], 'WAITING_FOR_KEY')
        with patch('intercept.run_factorization', return_value=measured_fixture()) as factor:
            entries = self.queue.decrypt_all()
            self.assertEqual([entry['text'] for entry in entries], ['Hello quantum 🔐', 'Reply'])
            self.assertEqual(self.queue.decrypt_all(), [])
            factor.assert_called_once_with(seed=42, modulus=33, base=5)
        self.assertEqual(self.queue.status()[0]['state'], 'DECRYPTED')
        exported = self.directory / 'transcripts' / 'chat.jsonl'
        self.assertEqual(self.queue.export(exported), 2)
        text = exported.read_text(encoding='utf-8')
        self.assertNotIn(self.master.hex(), text)
        self.assertNotIn('wrapped_key_digits', text)
        with self.assertRaises(FileExistsError):
            self.queue.export(exported)
        with self.assertRaises(CaptureError):
            self.queue.export(self.capture)

    def test_new_sessions_use_recovered_rsa_key_without_another_simulation(self):
        self.handshake()
        self.message(text='first session')
        with patch('intercept.run_factorization', return_value=measured_fixture()) as factor:
            self.queue.decrypt_all()
            header, master = create_session('Carol', 'Dave')
            self.handshake(header, 'flow-2')
            self.message('b_to_a', text='new session', header=header, master=master,
                         connection='flow-2')
            recovered = self.queue.decrypt_all()
            self.assertEqual([record['text'] for record in recovered], ['new session'])
            self.assertEqual(factor.call_count, 1)
            self.assertEqual(len(self.queue.sessions), 2)

    def test_capture_continues_while_simulation_runs(self):
        self.handshake()
        self.message(text='before quantum')
        def during_simulation(**kwargs):
            self.message(sequence=1, text='during quantum')
            return measured_fixture()
        with patch('intercept.run_factorization', side_effect=during_simulation):
            entries = self.queue.decrypt_all()
        self.assertEqual([entry['text'] for entry in entries], ['before quantum', 'during quantum'])

    def test_failed_quantum_recovery_leaves_queue_and_follow_does_not_retry(self):
        self.handshake()
        self.message()
        with patch('intercept.run_factorization', side_effect=AttackFailure('timed out')) as factor:
            self.assertEqual(self.queue.decrypt_all(retry=False), [])
            self.assertEqual(self.queue.decrypt_all(retry=False), [])
            self.assertEqual(factor.call_count, 1)
        session = self.queue.sessions[self.header['session_id']]
        self.assertIsNone(session.master)
        self.assertFalse(self.queue.private_exponents)
        self.assertEqual(self.queue.status()[0]['pending'], 1)
        self.assertFalse(self.queue.transcript)
        with patch('intercept.run_factorization', return_value=measured_fixture()):
            self.assertEqual(len(self.queue.decrypt_all()), 1)

    def test_invalid_factor_result_cannot_be_cached(self):
        self.handshake()
        evidence = measured_fixture()
        evidence['factors'] = [2, 16]
        with patch('intercept.run_factorization', return_value=evidence):
            self.assertEqual(self.queue.recover(), 0)
        self.assertFalse(self.queue.private_exponents)
        self.assertIsNone(self.queue.sessions[self.header['session_id']].master)

    def test_authentication_failure_does_not_release_text_or_advance_counter(self):
        self.handshake()
        correct = encrypt_record(self.header, self.master, 'a_to_b', 0, 'DO NOT LEAK')
        tampered = copy.deepcopy(correct)
        cipher = tampered['ciphertext_and_tag_hex']
        tampered['ciphertext_and_tag_hex'] = ('1' if cipher[0] != '1' else '2') + cipher[1:]
        self.append(self.event(tampered))
        self.append(self.event(correct))
        with patch('intercept.run_factorization', return_value=measured_fixture()):
            entries = self.queue.decrypt_all()
        self.assertEqual(len(entries), 1)
        session = self.queue.sessions[self.header['session_id']]
        self.assertEqual(session.next_sequence['a_to_b'], 1)
        self.assertEqual(session.error_count, 1)
        self.assertNotIn('DO NOT LEAK', self.queue.messages[0].error)
        self.assertEqual(self.queue.status()[0]['state'], 'INCOMPLETE_OR_INVALID')

    def test_replay_and_gap_are_rejected_without_complete_claim(self):
        self.handshake()
        frame = self.message(text='one copy')
        self.append(self.event(frame))
        self.message(sequence=3, text='must not pass gap')
        with patch('intercept.run_factorization', return_value=measured_fixture()):
            entries = self.queue.decrypt_all()
        self.assertEqual([entry['text'] for entry in entries], ['one copy'])
        self.assertEqual(self.queue.status()[0]['errors'], 2)
        self.assertEqual(self.queue.status()[0]['state'], 'INCOMPLETE_OR_INVALID')

    def test_missing_handshake_wrong_flow_and_direction_are_not_decrypted(self):
        self.message(text='no handshake')
        self.handshake()
        valid = encrypt_record(self.header, self.master, 'a_to_b', 0, 'bad direction')
        self.append(self.event(valid, 'b_to_a'))
        other_header, other_master = create_session('Eve', 'Mallory')
        wrong = encrypt_record(other_header, other_master, 'a_to_b', 0, 'wrong session')
        self.append(self.event(wrong))
        with patch('intercept.run_factorization', return_value=measured_fixture()):
            self.assertEqual(self.queue.decrypt_all(), [])
        self.assertEqual(self.queue.unassigned_records, 1)
        self.assertEqual(len(self.queue.errors), 3)
        self.assertFalse(self.queue.transcript)

    def test_malformed_capture_does_not_hide_valid_later_handshake(self):
        self.capture.write_bytes(b'{broken}\n{"event":"frame","event":"other"}\n')
        self.handshake()
        self.assertEqual(self.queue.refresh(), 3)
        self.assertEqual(len(self.queue.errors), 2)
        self.assertEqual(len(self.queue.sessions), 1)
        self.capture.write_bytes(b'')
        with self.assertRaisesRegex(CaptureError, 'truncated'):
            self.queue.refresh()

    def test_duplicate_handshake_does_not_replace_session_state(self):
        self.handshake()
        self.message()
        self.handshake()
        self.queue.refresh()
        self.assertEqual(len(self.queue.sessions), 1)
        self.assertEqual(len(self.queue.messages), 1)
        self.assertEqual(len(self.queue.errors), 1)
        self.assertEqual(self.queue.status()[0]['errors'], 1)

    def test_capture_reconstruction_error_marks_affected_session_incomplete(self):
        self.append({'event': 'capture_error', 'connection_id': 'flow-1',
                     'direction': 'a_to_b', 'time_ns': 0, 'error': 'capture started midstream'})
        self.handshake()
        self.message(text='authenticated but incomplete stream')
        self.assertEqual(self.queue.status()[0]['state'], 'WAITING_FOR_KEY_WITH_ERRORS')
        with patch('intercept.run_factorization', return_value=measured_fixture()):
            self.assertEqual(len(self.queue.decrypt_all()), 1)
        self.assertEqual(self.queue.status()[0]['state'], 'INCOMPLETE_OR_INVALID')
        self.append({'event': 'capture_error', 'connection_id': 'flow-1',
                     'direction': 'b_to_a', 'time_ns': 4, 'error': 'truncated frame'})
        self.assertEqual(self.queue.status()[0]['errors'], 2)

    def test_batch_rejects_incomplete_tail_even_after_all_messages_decrypt(self):
        self.handshake()
        self.message(text='complete authenticated record')
        with self.capture.open('ab') as stream:
            stream.write(b'{"event":"frame"')
        output = io.StringIO()
        with patch('intercept.run_factorization', return_value=measured_fixture()), redirect_stdout(output):
            result = main(['--capture', str(self.capture), '--decrypt-all'])
        self.assertEqual(result, 1)
        self.assertIn('complete authenticated record', output.getvalue())
        self.assertIn('incomplete JSONL', output.getvalue())


if __name__ == '__main__':
    unittest.main()
