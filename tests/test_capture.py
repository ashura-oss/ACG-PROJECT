"""Passive stream reconstruction tests; packets here are synthetic fixtures."""
import unittest

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from capture import CaptureError, MAX_BUFFER_BYTES, PacketObserver, TCPStream
from chat_protocol import MAX_FRAME_BYTES, encode_frame


class TCPStreamTests(unittest.TestCase):
    def test_segmentation_coalescing_and_identical_retransmission(self):
        first = encode_frame({'type': 'one'})
        second = encode_frame({'type': 'two'})
        wire = first + second
        stream = TCPStream()
        stream.start(100)
        self.assertEqual(stream.feed(106, wire[5:]), [])
        frames = stream.feed(101, wire[:8])
        self.assertEqual([frame['type'] for _, frame in frames], ['one', 'two'])
        self.assertEqual(b''.join(raw for raw, _ in frames), wire)
        self.assertEqual(stream.feed(101, wire), [])
        stream.end(101 + len(wire))
        self.assertTrue(stream.closed)
        stream.finish()

    def test_sequence_wrap_with_reordered_payload(self):
        modulus = 2**32
        initial = modulus - 5
        wire = encode_frame({'type': 'wrapped'})
        stream = TCPStream()
        stream.start(initial)
        self.assertEqual(stream.feed((initial + 1 + 9) % modulus, wire[9:]), [])
        frames = stream.feed((initial + 1) % modulus, wire[:9])
        self.assertEqual(frames, [(wire, {'type': 'wrapped'})])
        stream.end((initial + 1 + len(wire)) % modulus)
        self.assertTrue(stream.closed)

    def test_fin_before_missing_data_is_deferred(self):
        wire = encode_frame({'type': 'complete'})
        stream = TCPStream()
        stream.start(10)
        stream.end(11 + len(wire))
        self.assertFalse(stream.closed)
        self.assertEqual(stream.feed(18, wire[7:]), [])
        frames = stream.feed(11, wire[:7])
        self.assertEqual(frames, [(wire, {'type': 'complete'})])
        self.assertTrue(stream.closed)
        stream.finish()

    def test_fin_with_unfilled_gap_is_explicit_at_capture_eof(self):
        stream = TCPStream()
        stream.start(10)
        stream.end(50)
        with self.assertRaisesRegex(CaptureError, 'Incomplete TCP stream'):
            stream.finish()

    def test_conflicting_pending_and_retransmitted_bytes_are_rejected(self):
        pending = TCPStream()
        pending.start(100)
        pending.feed(105, b'abcdef')
        with self.assertRaisesRegex(CaptureError, 'Conflicting overlapping'):
            pending.feed(107, b'XX')

        committed = TCPStream()
        committed.start(100)
        wire = encode_frame({'type': 'done'})
        committed.feed(101, wire)
        with self.assertRaisesRegex(CaptureError, 'Conflicting retransmitted'):
            committed.feed(101, b'X' + wire[1:])

    def test_missing_syn_and_bounded_capture_fail_explicitly(self):
        with self.assertRaisesRegex(CaptureError, 'Missing TCP handshake'):
            TCPStream().feed(100, b'{}\n')
        gap = TCPStream()
        gap.start(100)
        with self.assertRaisesRegex(CaptureError, 'reassembly window'):
            gap.feed(101 + MAX_BUFFER_BYTES + 1, b'x')
        buffer = TCPStream()
        buffer.start(100)
        with self.assertRaisesRegex(CaptureError, 'buffer limit'):
            buffer.feed(101, b'x' * (MAX_BUFFER_BYTES + 1))

    def test_oversized_malformed_and_truncated_frames_are_rejected(self):
        for payload in (b' ' * MAX_FRAME_BYTES + b'\n',
                        b'x' * MAX_FRAME_BYTES, b'{bad json}\n',
                        b'{"x":1,"x":2}\n'):
            stream = TCPStream()
            stream.start(100)
            with self.assertRaises(ValueError):
                stream.feed(101, payload)
        stream = TCPStream()
        stream.start(100)
        stream.feed(101, b'{"unfinished":')
        with self.assertRaisesRegex(CaptureError, 'truncated chat frame'):
            stream.finish()

    def test_new_data_after_fin_and_conflicting_fin_are_rejected(self):
        wire = encode_frame({'type': 'done'})
        stream = TCPStream()
        stream.start(100)
        stream.feed(101, wire)
        stream.end(101 + len(wire))
        self.assertEqual(stream.feed(101, wire), [])
        with self.assertRaisesRegex(CaptureError, 'after stream close'):
            stream.feed(101 + len(wire), b'{}\n')
        with self.assertRaisesRegex(CaptureError, 'Conflicting TCP FIN'):
            stream.end(102 + len(wire))


class PacketObserverTests(unittest.TestCase):
    def packet(self, direction, sequence, flags='PA', payload=b'', ipv6=False):
        network = IPv6(src='::1', dst='::1') if ipv6 else IP(src='127.0.0.1', dst='127.0.0.1')
        sport, dport = (41000, 9001) if direction == 'a_to_b' else (9001, 41000)
        packet = network / TCP(sport=sport, dport=dport, seq=sequence, flags=flags)
        if payload:
            packet /= payload
        return packet

    def test_observer_both_directions_and_fin_before_data(self):
        events = []
        observer = PacketObserver(9001, events.append)
        first = encode_frame({'type': 'alice-frame'})
        second = encode_frame({'type': 'bob-frame'})
        observer.consume(self.packet('a_to_b', 100, 'S'))
        observer.consume(self.packet('b_to_a', 200, 'SA'))
        observer.consume(self.packet('a_to_b', 101 + len(first), 'FA'))
        observer.consume(self.packet('a_to_b', 101, payload=first))
        observer.consume(self.packet('b_to_a', 201, payload=second))
        observer.consume(self.packet('b_to_a', 201, payload=second))
        observer.finish()
        self.assertEqual(observer.errors, 0)
        self.assertEqual(observer.frames, 2)
        self.assertEqual([event['direction'] for event in events], ['a_to_b', 'b_to_a'])
        self.assertEqual(len({event['connection_id'] for event in events}), 1)
        self.assertEqual(bytes.fromhex(events[0]['wire_hex']), first)

    def test_ipv6_loopback_uses_same_reassembly(self):
        events = []
        observer = PacketObserver(9001, events.append)
        wire = encode_frame({'type': 'ipv6-frame'})
        observer.consume(self.packet('a_to_b', 100, 'S', ipv6=True))
        observer.consume(self.packet('a_to_b', 101, payload=wire, ipv6=True))
        observer.finish()
        self.assertEqual(observer.errors, 0)
        self.assertEqual(events[0]['frame']['type'], 'ipv6-frame')

    def ethernet(self, packet, padding=0):
        """Serialize then parse, so IP's declared length excludes Ethernet padding."""
        raw = bytes(Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / packet)
        return Ether(raw + b'\x00' * max(padding, 60 - len(raw)))

    def test_ethernet_padding_is_not_tcp_payload(self):
        events = []
        observer = PacketObserver(9001, events.append)
        observer.consume(self.ethernet(self.packet('a_to_b', 100, 'S')))
        # Even a short application frame can have padding after its IP datagram.
        observer.consume(self.ethernet(self.packet('a_to_b', 101, payload=b'{}\n')))
        observer.consume(self.ethernet(self.packet('a_to_b', 104, 'A')))
        observer.finish()
        self.assertEqual(observer.errors, 0)
        self.assertEqual(observer.frames, 1)
        self.assertEqual(events[0]['wire_hex'], b'{}\n'.hex())

    def test_padding_after_ipv6_datagram_is_not_tcp_payload(self):
        events = []
        observer = PacketObserver(9001, events.append)
        observer.consume(self.ethernet(self.packet('a_to_b', 100, 'S', ipv6=True), padding=8))
        observer.consume(self.ethernet(self.packet('a_to_b', 101, payload=b'{}\n', ipv6=True), padding=8))
        observer.finish()
        self.assertEqual(observer.errors, 0)
        self.assertEqual(observer.frames, 1)

    def test_snaplen_truncated_ip_payload_reports_error_immediately(self):
        events = []
        observer = PacketObserver(9001, events.append)
        observer.consume(self.ethernet(self.packet('a_to_b', 100, 'S')))
        wire = encode_frame({'type': 'snaplen-truncated'})
        complete = self.ethernet(self.packet('a_to_b', 101, payload=wire))
        truncated = Ether(bytes(complete)[:-3])
        observer.consume(truncated)
        self.assertEqual(observer.frames, 0)
        self.assertEqual(observer.errors, 1)
        self.assertIn('truncated', events[0]['error'].lower())

    def test_capture_starting_midstream_produces_error_not_fabricated_frame(self):
        events = []
        observer = PacketObserver(9001, events.append)
        observer.consume(self.packet('a_to_b', 100, payload=encode_frame({'type': 'late'})))
        observer.consume(self.packet('a_to_b', 120, payload=encode_frame({'type': 'later'})))
        observer.finish()
        self.assertEqual(observer.frames, 0)
        self.assertEqual(observer.errors, 1)
        self.assertEqual(events[0]['event'], 'capture_error')
        self.assertIn('Missing TCP handshake', events[0]['error'])

    def test_missing_segment_at_eof_and_conflicting_overlap_fail_closed(self):
        for first_payload, subsequent_sequence, subsequent_payload in (
                (b'{"type":"partial', 130, b'"}\n'),
                (b'{"type":"done"}\n', 101, b'{"type":"evil"}\n')):
            events = []
            observer = PacketObserver(9001, events.append)
            observer.consume(self.packet('a_to_b', 100, 'S'))
            observer.consume(self.packet('a_to_b', 101, payload=first_payload))
            observer.consume(self.packet('a_to_b', subsequent_sequence, payload=subsequent_payload))
            observer.finish()
            self.assertEqual(observer.errors, 1)
            self.assertEqual(sum(event['event'] == 'capture_error' for event in events), 1)


if __name__ == '__main__':
    unittest.main()
