"""Tests for the crypto, the Shor crack, the chat network and the sniffer's reassembly."""
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import network
import shor
from interceptor_app import Stream
from protocol import (ProtocolError, create_pqc_session, create_rsa_session, decrypt_message, encode_frame,
                      encrypt_message, generate_pqc_key, pqc_public, unlock_pqc_key, unlock_rsa_key, validate_header)


class Crypto(unittest.TestCase):
    def test_rsa_lock(self):
        for _ in range(20):
            key = network.random_rsa_key()
            self.assertEqual(key['N'].bit_length(), 7)
            header, aes = create_rsa_session('Alice', 'Bob', key['N'], key['e'])
            self.assertEqual(unlock_rsa_key(header, key['d']), aes)
            frame = encrypt_message(header, aes, 'a_to_b', 0, 'hi')
            self.assertEqual(decrypt_message(header, aes, frame), 'hi')

    def test_pqc_lock(self):
        key = generate_pqc_key()
        header, aes = create_pqc_session('Alice', 'Bob', pqc_public(key))
        self.assertEqual(unlock_pqc_key(header, key), aes)
        self.assertNotEqual(unlock_pqc_key(header, generate_pqc_key()), aes)

    def test_tampering_is_rejected(self):
        key = network.random_rsa_key()
        header, aes = create_rsa_session('Alice', 'Bob', key['N'], key['e'])
        frame = encrypt_message(header, aes, 'a_to_b', 0, 'hi')
        with self.assertRaises(ProtocolError):
            decrypt_message(header, aes, {**frame, 'sequence': 1})
        with self.assertRaises(ProtocolError):
            validate_header({**header, 'N': 33})


class Shor(unittest.TestCase):
    def test_crack_recovers_the_aes_key(self):
        key = network.random_rsa_key()
        header, aes = create_rsa_session('Alice', 'Bob', key['N'], key['e'])
        found = shor.crack(key['N'], seed=1)
        p, q = found['factors']
        self.assertEqual(p * q, key['N'])
        d = pow(key['e'], -1, (p - 1) * (q - 1))
        self.assertEqual(unlock_rsa_key(header, d), aes)


class Network(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        patcher = mock.patch.object(network, 'FOLDER', Path(folder.name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def pair(self, mode_a, mode_b):
        got, done = [], threading.Event()

        def node(name, mode):
            n = network.Node(network.Me(name, mode), on_chat=lambda c: None,
                             on_text=lambda c, t: (got.append(t), done.set()), on_end=lambda c: None)
            self.addCleanup(n.stop)
            return n
        return node('Alice', mode_a), node('Bob', mode_b), got, done

    def test_chat_both_modes(self):
        for mode in ('rsa', 'pqc'):
            alice, bob, got, done = self.pair(mode, mode)
            chats = []
            alice.on_chat = chats.append
            alice.dial(bob.port)
            chats[0].send('hello Bob')
            self.assertTrue(done.wait(5))
            self.assertEqual(got, ['hello Bob'])

    def test_different_locks_cannot_chat(self):
        alice, bob, _, _ = self.pair('rsa', 'pqc')
        with self.assertRaises((ProtocolError, OSError)):
            alice.dial(bob.port)

    def test_discovery_by_mode(self):
        a, b, c = network.Me('Alice', 'rsa'), network.Me('Bob', 'rsa'), network.Me('Carol', 'pqc')
        for me, port in ((a, 1), (b, 2), (c, 3)):
            network.announce(me, port)
        self.assertEqual([p['name'] for p in network.online('rsa', exclude=a.id)], ['Bob'])
        network.leave(c)
        self.assertEqual(network.online('pqc'), [])


class Reassembly(unittest.TestCase):
    def test_out_of_order_and_retransmitted_segments(self):
        line = encode_frame({'type': 'ready'}) + encode_frame({'type': 'x'})
        stream = Stream(1000)
        self.assertEqual(stream.feed(1005, line[5:]), [])
        first = len(encode_frame({'type': 'ready'}))
        self.assertEqual(stream.feed(1000, line[:5]), [line[:first], line[first:]])
        self.assertEqual(stream.feed(1000, line[:5]), [])


if __name__ == '__main__':
    unittest.main()
