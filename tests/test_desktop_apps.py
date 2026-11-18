"""Desktop apps: toy RSA lock, general Shor crack, discovery, handshakes, capture range."""
import json
import math
from pathlib import Path
import random
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capture import PacketObserver
from chat_protocol import (ProtocolError, create_toy_session, decrypt_record, encrypt_record,
                           recover_master, toy_digit_count, validate_header)
from intercept import CaptureQueue
from interceptor_app import crack_session
import peer_net
from peer_net import Identity, Node, Registry, generate_toy_rsa


class ToyRsaTests(unittest.TestCase):
    def test_key_generation(self):
        rng = random.Random(1)
        for _ in range(50):
            key = generate_toy_rsa(rng=rng)
            self.assertEqual(key['N'].bit_length(), 7)
            self.assertEqual(key['N'] % 2, 1)
            for value in range(key['N']):
                self.assertEqual(pow(pow(value, key['e'], key['N']), key['d'], key['N']), value)

    def test_session_round_trip_and_wrong_key(self):
        key = generate_toy_rsa(rng=random.Random(2))
        header, master = create_toy_session('Alice', 'Bob', (key['N'], key['e']))
        self.assertEqual(len(header['wrapped_key_digits']), toy_digit_count(key['N']))
        self.assertEqual(recover_master(header, key['d']), master)
        frame = encrypt_record(header, master, 'a_to_b', 0, 'hello')
        self.assertEqual(decrypt_record(header, master, frame), 'hello')
        wrong = key['d'] + 1 if key['d'] + 1 < key['N'] else key['d'] - 1
        try:
            self.assertNotEqual(recover_master(header, wrong), master)
        except ProtocolError:
            pass

    def test_header_validation(self):
        key = generate_toy_rsa(rng=random.Random(3))
        header, _ = create_toy_session('Alice', 'Bob', (key['N'], key['e']))
        for change in ({'N': 33}, {'N': 1024 + 1}, {'e': 1}, {'wrapped_key_digits': [0]},
                       {'key_encoding': 'RSA-OAEP-SHA256'}):
            with self.assertRaises(ProtocolError):
                validate_header({**header, **change})


class ShorCrackTests(unittest.TestCase):
    def test_crack_recovers_the_aes_key_from_public_data_only(self):
        key = generate_toy_rsa(rng=random.Random(4))
        header, master = create_toy_session('Alice', 'Bob', (key['N'], key['e']))
        messages = []
        evidence, phi, d, recovered = crack_session(header, messages.append)
        p, q = evidence['factors']
        self.assertEqual(p * q, key['N'])
        self.assertEqual(math.gcd(evidence['base'], key['N']), 1)
        self.assertEqual(pow(evidence['base'], evidence['order'], key['N']), 1)
        self.assertEqual(recovered, master)
        self.assertTrue(messages)


class DiscoveryTests(unittest.TestCase):
    def test_peers_are_filtered_by_mode_and_expire(self):
        with tempfile.TemporaryDirectory() as folder:
            registry = Registry(folder)
            alice, bob, carol = Identity('Alice', 'rsa'), Identity('Bob', 'rsa'), Identity('Carol', 'pqc')
            for identity, port in ((alice, 1), (bob, 2), (carol, 3)):
                registry.announce(identity, port)
            self.assertEqual([p['name'] for p in registry.peers('rsa', exclude=alice.peer_id)], ['Bob'])
            self.assertEqual([p['name'] for p in registry.peers('pqc')], ['Carol'])
            self.assertTrue(registry.name_taken('bob'))
            stale = json.loads((Path(folder) / f'{bob.peer_id}.json').read_text())
            stale['updated'] -= 10
            (Path(folder) / f'{bob.peer_id}.json').write_text(json.dumps(stale))
            self.assertEqual(registry.peers('rsa', exclude=alice.peer_id), [])
            registry.withdraw(carol)
            self.assertEqual(registry.peers('pqc'), [])


class NodeTests(unittest.TestCase):
    def _pair(self, mode_a, mode_b):
        events = []
        done = threading.Event()

        def make(identity):
            return Node(identity, on_session=lambda s: events.append(('session', identity.name, s)),
                        on_message=lambda s, t: (events.append(('message', identity.name, t)), done.set()),
                        on_closed=lambda s, e: None, on_error=lambda e: events.append(('error', identity.name, e)))
        a, b = make(Identity('Alice', mode_a)), make(Identity('Bob', mode_b))
        return a, b, events, done

    def test_rsa_and_pqc_chats(self):
        for mode in ('rsa', 'pqc'):
            a, b, events, done = self._pair(mode, mode)
            try:
                session = a.dial(b.port)
                self.assertEqual(session.peer, 'Bob')
                session.send('hi Bob')
                self.assertTrue(done.wait(5))
                self.assertIn(('message', 'Bob', 'hi Bob'), events)
                self.assertEqual(session.header['version'], 5 if mode == 'rsa' else 4)
            finally:
                a.stop()
                b.stop()

    def test_modes_cannot_talk_to_each_other(self):
        a, b, events, _ = self._pair('rsa', 'pqc')
        try:
            with self.assertRaises((ProtocolError, OSError)):
                a.dial(b.port)
        finally:
            a.stop()
            b.stop()


class CaptureRangeTests(unittest.TestCase):
    def test_port_range_directions(self):
        from scapy.layers.inet import IP, TCP
        emitted = []
        observer = PacketObserver((47100, 47199), emitted.append)
        key = generate_toy_rsa(rng=random.Random(5))
        header, master = create_toy_session('Alice', 'Bob', (key['N'], key['e']))
        line = (json.dumps({'type': 'session', 'header': header}, separators=(',', ':'), sort_keys=True) + '\n').encode()
        syn = IP(src='127.0.0.1', dst='127.0.0.1') / TCP(sport=50000, dport=47123, flags='S', seq=100)
        data = IP(src='127.0.0.1', dst='127.0.0.1') / TCP(sport=50000, dport=47123, flags='PA', seq=101) / line
        ignored = IP(src='127.0.0.1', dst='127.0.0.1') / TCP(sport=50000, dport=9001, flags='S', seq=1)
        for packet in (syn, data, ignored):
            packet.time = time.time()
            observer.consume(IP(bytes(packet)))
        frames = [event for event in emitted if event['event'] == 'frame']
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]['direction'], 'a_to_b')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'cap.jsonl'
            path.write_text(json.dumps(frames[0]) + '\n')
            queue = CaptureQueue(path, output=lambda message: None)
            queue.refresh()
            self.assertEqual(len(queue.sessions), 1)


if __name__ == '__main__':
    unittest.main()
