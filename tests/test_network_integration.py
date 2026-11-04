"""Actual TCP peer processes plus a separately labelled synthetic-PCAP attack test."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def command(script, *arguments):
    return [sys.executable, '-u', str(ROOT / script), *map(str, arguments)]


class NetworkIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environment = {**os.environ, 'PYTHONIOENCODING': 'utf-8',
                            'PYTHONUNBUFFERED': '1'}

    def run_cli(self, script, *arguments, timeout=45):
        result = subprocess.run(command(script, *arguments), cwd=self.directory,
                                env=self.environment, capture_output=True,
                                text=True, encoding='utf-8', timeout=timeout)
        self.assertEqual(result.returncode, 0, result.stdout + '\n' + result.stderr)
        return result

    def start_peer(self, label, *arguments):
        path = self.directory / (label + '.log')
        stream = path.open('w', encoding='utf-8')
        self.addCleanup(stream.close)
        process = subprocess.Popen(command('chat.py', *arguments),
                                   cwd=self.directory, env=self.environment,
                                   stdin=subprocess.PIPE, stdout=stream,
                                   stderr=subprocess.STDOUT, text=True,
                                   encoding='utf-8', bufsize=1)

        def stop():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stdin:
                process.stdin.close()
        self.addCleanup(stop)
        return process, path

    def wait_for_log(self, process, path, expected, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = path.read_text(encoding='utf-8')
            if expected in text:
                return text
            if process.poll() is not None:
                self.fail(f'Peer exited before {expected!r}:\n{text}')
            time.sleep(0.05)
        self.fail(f'Timed out waiting for {expected!r}:\n'
                  + path.read_text(encoding='utf-8'))

    def test_real_tcp_chat_subprocesses_exchange_both_directions(self):
        """No capture driver, relay, fixture packets, or mocked crypto is involved."""
        key_path = self.directory / 'bob-private.json'
        self.run_cli('chat.py', 'setup', '--key-file', key_path)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        bob, bob_log = self.start_peer('bob', 'listen', '--host', '127.0.0.1',
                                       '--port', port, '--name', 'Bob',
                                       '--key-file', key_path)
        self.wait_for_log(bob, bob_log, 'Listening on')
        alice, alice_log = self.start_peer('alice', 'connect', '--host',
                                           '127.0.0.1', '--port', port,
                                           '--name', 'Alice')
        self.wait_for_log(alice, alice_log, 'Connected session')
        self.wait_for_log(bob, bob_log, 'Connected session')

        alice.stdin.write('ALICE_TO_BOB_7d69 🔐\n')
        alice.stdin.flush()
        bob.stdin.write('BOB_TO_ALICE_49e2 hello\n')
        bob.stdin.flush()
        self.wait_for_log(bob, bob_log, 'ALICE_TO_BOB_7d69 🔐')
        self.wait_for_log(alice, alice_log, 'BOB_TO_ALICE_49e2 hello')

        # Input rejection must not destroy a healthy encrypted connection.
        alice.stdin.write('x' * 4097 + '\nAFTER_OVERSIZE_84b1\n')
        alice.stdin.flush()
        self.wait_for_log(bob, bob_log, 'AFTER_OVERSIZE_84b1')
        alice.stdin.write('/quit\n')
        alice.stdin.flush()
        self.assertEqual(alice.wait(timeout=10), 0,
                         alice_log.read_text(encoding='utf-8'))
        self.assertEqual(bob.wait(timeout=10), 0,
                         bob_log.read_text(encoding='utf-8'))

    def test_synthetic_pcap_import_and_fresh_process_quantum_recovery(self):
        """Synthetic packet fixture, not a claim that live OS sniffing was tested."""
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
        from chat_protocol import create_session, encode_frame, encrypt_record

        header, master = create_session('Alice', 'Bob')
        greeting = encode_frame({'type': 'public_key', 'protocol': 'ACG-CHAT',
                                 'version': 1, 'N': 33, 'e': 3, 'name': 'Bob'})
        hello = encode_frame({'type': 'session', 'header': header})
        ready = encode_frame({'type': 'ready', 'session_id': header['session_id']})
        alice_message = 'PCAP_ALICE_8013 quantum 🔐'
        bob_message = 'PCAP_BOB_6824 reply'
        a_record = encode_frame(encrypt_record(header, master, 'a_to_b', 0,
                                               alice_message))
        b_record = encode_frame(encrypt_record(header, master, 'b_to_a', 0,
                                               bob_message))
        packets = []
        client_port, server_port = 43123, 9001

        def packet(from_alice, seq, ack, flags='PA', payload=b''):
            sport, dport = ((client_port, server_port) if from_alice
                            else (server_port, client_port))
            value = (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') /
                     IP(src='127.0.0.1', dst='127.0.0.1') /
                     TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags))
            if payload:
                value /= Raw(payload)
            value.time = 1700000000 + len(packets) / 1000
            packets.append(value)

        packet(True, 1000, 0, 'S')
        packet(False, 5000, 1001, 'SA')
        packet(True, 1001, 5001, 'A')
        packet(False, 5001, 1001, payload=greeting)
        split = len(hello) // 2
        # Deliberate out-of-order delivery after observed SYN sequence numbers.
        packet(True, 1001 + split, 5001 + len(greeting), payload=hello[split:])
        packet(True, 1001, 5001 + len(greeting), payload=hello[:split])
        a_next = 1001 + len(hello)
        b_next = 5001 + len(greeting)
        packet(False, b_next, a_next, payload=ready + b_record)
        b_next += len(ready) + len(b_record)
        packet(True, a_next, b_next, payload=a_record)
        # TCP retransmission must not become a replayed application message.
        packet(True, a_next, b_next, payload=a_record)
        packet(True, a_next + len(a_record), b_next, 'FA')
        packet(False, b_next, a_next + len(a_record) + 1, 'FA')

        pcap = self.directory / 'synthetic-chat.pcap'
        capture = self.directory / 'capture.jsonl'
        wrpcap(str(pcap), packets)
        self.run_cli('capture.py', '--pcap', pcap, '--port', server_port,
                     '--output', capture)
        events = [json.loads(line) for line in
                  capture.read_text(encoding='utf-8').splitlines()]
        frames = [row['frame'] for row in events if row.get('event') == 'frame']
        messages = [row for row in frames if row.get('type') == 'message']
        self.assertEqual(len(messages), 2, 'Retransmitted TCP data was duplicated')
        self.assertEqual(sum(row.get('type') == 'session' for row in frames), 1)
        self.assertNotIn(master.hex(), capture.read_text(encoding='utf-8'))
        self.assertNotIn(alice_message, capture.read_text(encoding='utf-8'))
        self.assertNotIn(bob_message, capture.read_text(encoding='utf-8'))

        # This new process receives only a public capture path and simulator seed.
        result = self.run_cli('intercept.py', '--capture', capture,
                              '--decrypt-all', '--seed', 42, timeout=45)
        self.assertIn(alice_message, result.stdout)
        self.assertIn(bob_message, result.stdout)
        self.assertIn('RSA key recovered', result.stdout)

    def test_appended_sessions_share_one_real_quantum_recovery(self):
        """Real Shor runs once; later sessions unwrap from its recovered exponent."""
        from chat_protocol import create_session, encrypt_record
        from intercept import CaptureQueue
        from shor import run_factorization

        capture = self.directory / 'appending-capture.jsonl'
        output = []
        queue = CaptureQueue(capture, seed=42, output=output.append)
        ordinal = 0

        def append(connection, direction, frame):
            nonlocal ordinal
            ordinal += 1
            event = {'event': 'frame', 'connection_id': connection,
                     'direction': direction, 'time_ns': ordinal, 'frame': frame}
            with capture.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(event) + '\n')

        first_header, first_master = create_session('Alice', 'Bob')
        first_text = 'FIRST_SESSION_833b confidential'
        first_reply = 'FIRST_REPLY_e538 confidential'
        append('connection-one', 'a_to_b',
               {'type': 'session', 'header': first_header})
        append('connection-one', 'a_to_b', encrypt_record(
            first_header, first_master, 'a_to_b', 0, first_text))
        append('connection-one', 'b_to_a', encrypt_record(
            first_header, first_master, 'b_to_a', 0, first_reply))
        queue.refresh()
        self.assertEqual(queue.status()[0]['state'], 'WAITING_FOR_KEY')
        self.assertEqual(queue.decrypt_all(recover=False), [])
        self.assertEqual(queue.transcript, [])
        self.assertNotIn(first_text, '\n'.join(output))
        self.assertNotIn(first_reply, '\n'.join(output))

        # Count calls without replacing the real circuit execution or its data.
        with patch('intercept.run_factorization', wraps=run_factorization) as quantum:
            self.assertEqual(queue.recover(), 1)
            self.assertEqual(queue.evidence[(33, 3)]['order'], 10)
            self.assertEqual([row['text'] for row in queue.decrypt_all(recover=False)],
                             [first_text, first_reply])
            self.assertEqual(quantum.call_count, 1)

            second_header, second_master = create_session('Alice', 'Bob')
            self.assertNotEqual(first_header['session_id'], second_header['session_id'])
            self.assertNotEqual(first_master, second_master)
            second_text = 'SECOND_SESSION_2127 fresh secret'
            valid_zero = encrypt_record(second_header, second_master,
                                        'a_to_b', 0, second_text)
            tampered = dict(valid_zero)
            cipher = tampered['ciphertext_and_tag_hex']
            tampered['ciphertext_and_tag_hex'] = ('0' if cipher[0] != '0' else '1') + cipher[1:]
            append('connection-two', 'a_to_b',
                   {'type': 'session', 'header': second_header})
            append('connection-two', 'a_to_b', tampered)
            self.assertEqual(queue.decrypt_all(), [])
            self.assertEqual(quantum.call_count, 1)
            self.assertNotIn(second_text, '\n'.join(output))
            self.assertEqual(queue.sessions[second_header['session_id']].master,
                             second_master)

            # A corrupted candidate must not consume the expected sequence.
            # A later legitimate copy and its successor remain authenticatable.
            append('connection-two', 'a_to_b', valid_zero)
            second_next = 'SECOND_NEXT_15a3'
            append('connection-two', 'a_to_b', encrypt_record(
                second_header, second_master, 'a_to_b', 1, second_next))
            first_next = 'FIRST_STILL_ACTIVE_d2f6'
            append('connection-one', 'b_to_a', encrypt_record(
                first_header, first_master, 'b_to_a', 1, first_next))
            self.assertEqual([row['text'] for row in queue.decrypt_all()],
                             [second_text, second_next, first_next])
            self.assertEqual(quantum.call_count, 1)
            self.assertEqual(queue.decrypt_all(), [])
            self.assertEqual(len(queue.transcript), 5)

        summary = {row['session_id']: row for row in queue.status()}
        self.assertEqual(summary[first_header['session_id']]['state'], 'DECRYPTED')
        self.assertEqual(summary[second_header['session_id']]['errors'], 1)
        self.assertEqual(summary[second_header['session_id']]['decrypted'], 2)
        self.assertEqual(summary[second_header['session_id']]['pending'], 0)
        self.assertEqual(summary[second_header['session_id']]['state'],
                         'INCOMPLETE_OR_INVALID')

    @unittest.skipUnless(os.environ.get('ACG_LIVE_CAPTURE_INTERFACE'),
                         'Set ACG_LIVE_CAPTURE_INTERFACE to opt into OS packet capture')
    def test_optional_live_capture_quantum_recovery_and_independent_chat(self):
        """Capture real loopback packets; no fixture, proxy, or elevation is used."""
        interface = os.environ['ACG_LIVE_CAPTURE_INTERFACE']
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        capture_path = self.directory / 'live.jsonl'
        capture_lines = []
        ready = threading.Event()
        observer = subprocess.Popen(
            command('capture.py', '--interface', interface, '--port', port,
                    '--output', capture_path), cwd=self.directory,
            env=self.environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace')

        def drain_capture():
            for line in observer.stdout:
                capture_lines.append(line)
                if 'Capture ready' in line:
                    ready.set()

        drainer = threading.Thread(target=drain_capture, daemon=True)
        drainer.start()

        def stop_capture():
            if observer.poll() is None:
                observer.terminate()
                try:
                    observer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    observer.kill()
                    observer.wait(timeout=5)
            drainer.join(timeout=5)
            observer.stdout.close()
        self.addCleanup(stop_capture)

        deadline = time.monotonic() + 15
        while not ready.wait(timeout=0.05):
            if observer.poll() is not None:
                drainer.join(timeout=2)
                self.fail('Live capture initialization failed:\n' + ''.join(capture_lines))
            if time.monotonic() >= deadline:
                self.fail('Live capture did not become ready:\n' + ''.join(capture_lines))

        key_path = self.directory / 'live-bob-private.json'
        self.run_cli('chat.py', 'setup', '--key-file', key_path)
        bob, bob_log = self.start_peer('live-bob', 'listen', '--host',
                                       '127.0.0.1', '--port', port,
                                       '--name', 'Bob', '--key-file', key_path)
        self.wait_for_log(bob, bob_log, 'Listening on')
        alice, alice_log = self.start_peer('live-alice', 'connect', '--host',
                                           '127.0.0.1', '--port', port,
                                           '--name', 'Alice')
        self.wait_for_log(alice, alice_log, 'Connected session')
        self.wait_for_log(bob, bob_log, 'Connected session')
        alice_text = 'LIVE_ALICE_18bc quantum 🔐'
        bob_text = 'LIVE_BOB_f2a9 response'
        alice.stdin.write(alice_text + '\n')
        alice.stdin.flush()
        bob.stdin.write(bob_text + '\n')
        bob.stdin.flush()
        self.wait_for_log(bob, bob_log, alice_text)
        self.wait_for_log(alice, alice_log, bob_text)

        deadline = time.monotonic() + 10
        while True:
            raw = capture_path.read_text(encoding='utf-8') if capture_path.exists() else ''
            # A writer may still be appending its final JSONL event.
            events = [json.loads(line) for line in raw.splitlines(keepends=True)
                      if line.endswith('\n')]
            messages = [event for event in events if event.get('event') == 'frame'
                        and event['frame'].get('type') == 'message']
            if len(messages) >= 2:
                break
            if observer.poll() is not None or time.monotonic() >= deadline:
                self.fail('Actual chat messages were not captured:\n'
                          + ''.join(capture_lines) + '\n' + raw)
            time.sleep(0.05)
        self.assertNotIn(alice_text, raw)
        self.assertNotIn(bob_text, raw)
        recovered = self.run_cli('intercept.py', '--capture', capture_path,
                                 '--decrypt-all', '--seed', 42)
        self.assertIn(alice_text, recovered.stdout)
        self.assertIn(bob_text, recovered.stdout)
        self.assertIn('RSA key recovered', recovered.stdout)

        # The observer is not a relay: both directions must still work after it exits.
        stop_capture()
        capture_size = capture_path.stat().st_size
        alice.stdin.write('AFTER_OBSERVER_ALICE_92fa\n')
        alice.stdin.flush()
        bob.stdin.write('AFTER_OBSERVER_BOB_3f85\n')
        bob.stdin.flush()
        self.wait_for_log(bob, bob_log, 'AFTER_OBSERVER_ALICE_92fa')
        self.wait_for_log(alice, alice_log, 'AFTER_OBSERVER_BOB_3f85')
        self.assertEqual(capture_path.stat().st_size, capture_size)
        alice.stdin.write('/quit\n')
        alice.stdin.flush()
        self.assertEqual(alice.wait(timeout=10), 0)
        self.assertEqual(bob.wait(timeout=10), 0)


if __name__ == '__main__':
    unittest.main()
