"""Passive TCP packet capture and bounded chat-frame stream reconstruction.

The observer opens no connection to either peer and does not read endpoint keys.
Live capture requires Scapy plus an appropriate OS packet-capture driver/access.
Saved PCAP/PCAPNG input uses the identical reassembly path without privileges.
"""
import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys
import time
import uuid

from chat_protocol import MAX_FRAME_BYTES, decode_frame

MAX_BUFFER_BYTES = 1_048_576
MAX_CONNECTIONS = 256
_MODULUS = 1 << 32


class CaptureError(ValueError):
    pass


def tcp_payload(network, tcp):
    """Exclude Ethernet padding and reject packet-capture snapshot truncation."""
    network_wire = bytes(network)
    tcp_wire = bytes(tcp)
    tcp_header = int(tcp.dataofs) * 4 if tcp.dataofs is not None else len(tcp_wire) - len(bytes(tcp.payload))
    if tcp_header < 20:
        raise CaptureError('Invalid captured TCP header length')
    if network.version == 4:
        ip_header = int(network.ihl) * 4 if network.ihl is not None else len(network_wire) - len(bytes(network.payload))
        declared = int(network.len) if network.len is not None else len(network_wire)
        length = declared - ip_header - tcp_header
    else:
        declared = int(network.plen) if network.plen is not None else len(bytes(network.payload))
        extension_bytes = len(bytes(network.payload)) - len(tcp_wire)
        length = declared - extension_bytes - tcp_header
    payload = bytes(tcp.payload)
    if length < 0:
        raise CaptureError('Invalid captured IP/TCP length')
    if length > len(payload):
        raise CaptureError('Truncated captured TCP payload; capture full packet lengths')
    return payload[:length]


class TCPStream:
    """One direction, anchored by SYN; handles TCP wrap, overlap and reordering."""

    def __init__(self):
        self.next_sequence = None
        self.initial_sequence = None
        self.pending = []
        self.partial = bytearray()
        self.history = b''
        self.failed = False
        self.closed = False
        self.end_sequence = None

    def start(self, sequence):
        if self.initial_sequence is None:
            self.initial_sequence = sequence
            self.next_sequence = sequence + 1
        elif self.initial_sequence != sequence:
            raise CaptureError('Conflicting SYN in an existing TCP stream')

    def feed(self, sequence, payload):
        if self.failed or not payload:
            return []
        if self.next_sequence is None:
            raise CaptureError('Missing TCP handshake; start capture before connecting the chat')
        # Map 32-bit sequence numbers onto a local unwrapped coordinate system.
        delta = (sequence - self.next_sequence + (1 << 31)) % _MODULUS - (1 << 31)
        start = self.next_sequence + delta
        if abs(delta) > MAX_BUFFER_BYTES:
            raise CaptureError('TCP gap or retransmission exceeds reassembly window')
        if start < self.next_sequence:
            overlap_end = min(start + len(payload), self.next_sequence)
            history_start = self.next_sequence - len(self.history)
            compare_start = max(start, history_start)
            if compare_start < overlap_end:
                previous = self.history[compare_start-history_start:overlap_end-history_start]
                incoming = payload[compare_start-start:overlap_end-start]
                if previous != incoming:
                    raise CaptureError('Conflicting retransmitted TCP bytes')
            trim = min(self.next_sequence - start, len(payload))
            payload = payload[trim:]
            start += trim
        if not payload:
            return []
        if self.closed:
            raise CaptureError('New TCP payload after stream close')
        for old_start, old_data in self.pending:
            left, right = max(start, old_start), min(start+len(payload), old_start+len(old_data))
            if left < right and payload[left-start:right-start] != old_data[left-old_start:right-old_start]:
                raise CaptureError('Conflicting overlapping TCP segments')
        segments = sorted([*self.pending, (start, payload)], key=lambda row: row[0])
        merged = []
        for position, data in segments:
            if merged and position <= merged[-1][0] + len(merged[-1][1]):
                previous_start, previous_data = merged[-1]
                overlap = previous_start + len(previous_data) - position
                merged[-1] = previous_start, previous_data + data[max(0, overlap):]
            else:
                merged.append((position, data))
        if sum(len(data) for _, data in merged) > MAX_BUFFER_BYTES or len(merged) > 4096:
            raise CaptureError('TCP reassembly buffer limit exceeded')
        self.pending = merged
        frames = []
        while self.pending and self.pending[0][0] == self.next_sequence:
            _, data = self.pending.pop(0)
            self.next_sequence += len(data)
            self.history = (self.history + data)[-MAX_BUFFER_BYTES:]
            self.partial.extend(data)
            while True:
                newline = self.partial.find(b'\n')
                if newline < 0:
                    break
                line = bytes(self.partial[:newline+1])
                del self.partial[:newline+1]
                if len(line) > MAX_FRAME_BYTES:
                    raise CaptureError('Captured frame exceeds the protocol size limit')
                frames.append((line, decode_frame(line)))
            if len(self.partial) >= MAX_FRAME_BYTES:
                raise CaptureError('Unterminated captured frame exceeds the protocol size limit')
        if self.end_sequence is not None and self.next_sequence >= self.end_sequence:
            if self.next_sequence > self.end_sequence:
                raise CaptureError('TCP bytes extend past the captured FIN')
            self.finish()
            self.closed = True
        return frames

    def end(self, sequence):
        """FIN may arrive before earlier data; defer gap checks until EOF."""
        if self.next_sequence is None:
            self.closed = True
            return
        delta = (sequence - self.next_sequence + (1 << 31)) % _MODULUS - (1 << 31)
        end = self.next_sequence + delta
        if self.end_sequence is not None and self.end_sequence != end:
            raise CaptureError('Conflicting TCP FIN positions')
        self.end_sequence = end
        if end < self.next_sequence:
            raise CaptureError('TCP FIN precedes captured bytes')
        if end == self.next_sequence:
            self.finish()
            self.closed = True

    def finish(self):
        if self.failed:
            return
        if (self.pending or self.partial or (self.end_sequence is not None and
                                            self.next_sequence != self.end_sequence)):
            raise CaptureError('Incomplete TCP stream: missing segments or truncated chat frame')


@dataclass
class Connection:
    connection_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    streams: dict = field(default_factory=lambda: {'a_to_b': TCPStream(), 'b_to_a': TCPStream()})


class PacketObserver:
    """Convert captured packets to public JSONL events, without decryption."""

    def __init__(self, port, emit):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Chat port must be in 1..65535')
        self.port = port
        self.emit = emit
        self.connections = {}
        self.frames = 0
        self.errors = 0

    def _error(self, connection, direction, error, timestamp):
        self.errors += 1
        self.emit({'event': 'capture_error', 'connection_id': connection.connection_id,
                   'direction': direction, 'time_ns': timestamp, 'error': str(error)})
        connection.streams[direction].failed = True

    def consume(self, packet):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        if TCP not in packet or (IP not in packet and IPv6 not in packet):
            return
        tcp = packet[TCP]
        network = packet[IP] if IP in packet else packet[IPv6]
        if tcp.dport == self.port and tcp.sport != self.port:
            direction = 'a_to_b'
            key = (network.src, int(tcp.sport), network.dst, int(tcp.dport))
        elif tcp.sport == self.port and tcp.dport != self.port:
            direction = 'b_to_a'
            key = (network.dst, int(tcp.dport), network.src, int(tcp.sport))
        else:
            return
        timestamp = int(float(packet.time) * 1_000_000_000)
        syn = bool(int(tcp.flags) & 2)
        connection = self.connections.get(key)
        if connection is not None and direction == 'a_to_b' and syn:
            previous = connection.streams[direction].initial_sequence
            if previous is not None and previous != int(tcp.seq):
                for old_direction, old_stream in connection.streams.items():
                    try:
                        old_stream.finish()
                    except ValueError as error:
                        self._error(connection, old_direction, error, timestamp)
                connection = None
        if connection is None:
            if len(self.connections) >= MAX_CONNECTIONS and key not in self.connections:
                # Closed streams can be retired; active stream state must not be silently lost.
                retired = [k for k, c in self.connections.items()
                           if all(s.closed for s in c.streams.values())]
                for retired_key in retired:
                    del self.connections[retired_key]
                if len(self.connections) >= MAX_CONNECTIONS:
                    raise CaptureError('Too many active captured connections; start a new capture')
            connection = self.connections[key] = Connection()
        stream = connection.streams[direction]
        if stream.failed:
            return
        try:
            if IP in packet and (int(packet[IP].frag) or int(packet[IP].flags) & 1):
                raise CaptureError('Fragmented IP packet unsupported; use unfragmented chat traffic')
            if syn:
                stream.start(int(tcp.seq))
            payload = tcp_payload(network, tcp)
            for wire, frame in stream.feed((int(tcp.seq) + int(syn)) % _MODULUS,
                                            payload):
                self.emit({'event': 'frame', 'connection_id': connection.connection_id,
                           'direction': direction, 'time_ns': timestamp,
                           'frame': frame, 'wire_hex': wire.hex()})
                self.frames += 1
            if int(tcp.flags) & 1:
                stream.end((int(tcp.seq) + int(syn) + len(payload)) % _MODULUS)
            if int(tcp.flags) & 4:
                stream.finish()
                stream.closed = True
        except (ValueError, UnicodeError) as error:
            self._error(connection, direction, error, timestamp)

    def finish(self):
        for connection in self.connections.values():
            for direction, stream in connection.streams.items():
                try:
                    stream.finish()
                except ValueError as error:
                    self._error(connection, direction, error, time.time_ns())


def list_interfaces():
    from scapy.all import get_if_list, conf
    for name in get_if_list():
        try:
            description = conf.ifaces.dev_from_name(name).description
        except (ValueError, AttributeError):
            description = ''
        print(f'{name}\t{description}', flush=True)


def capture(args):
    from scapy.all import PcapReader, PcapWriter, conf, sniff
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Appending permits a stopped listener to resume without overwriting its queue.
    with output.open('a', encoding='utf-8', newline='\n') as stream:
        def emit(event):
            stream.write(json.dumps(event, ensure_ascii=True, separators=(',', ':')) + '\n')
            stream.flush()
        observer = PacketObserver(args.port, emit)
        raw_capture = None
        try:
            if args.pcap:
                if Path(args.pcap).resolve() == output.resolve():
                    raise ValueError('PCAP input and JSONL output must be different files')
                with PcapReader(args.pcap) as reader:
                    for packet in reader:
                        observer.consume(packet)
            else:
                if sys.platform == 'win32' and not conf.use_pcap:
                    raise RuntimeError('Live capture requires Npcap on Windows. Install Npcap, '
                                       'then select its loopback capture interface with --list-interfaces.')
                if args.pcap_out:
                    pcap_path = Path(args.pcap_out)
                    if pcap_path.resolve() == output.resolve():
                        raise ValueError('PCAP and JSONL output must be different files')
                    pcap_path.parent.mkdir(parents=True, exist_ok=True)
                    if pcap_path.exists():
                        raise FileExistsError('PCAP output already exists; choose a new --pcap-out file')
                    raw_capture = PcapWriter(str(pcap_path), sync=True)
                def observe(packet):
                    if raw_capture is not None:
                        raw_capture.write(packet)
                    observer.consume(packet)
                sniff(iface=args.interface, filter=f'tcp port {args.port}', store=False,
                      prn=observe,
                      started_callback=lambda: print(
                          f'Capture ready on {args.interface}, TCP port {args.port}.', flush=True))
        finally:
            observer.finish()
            if raw_capture is not None:
                raw_capture.close()
        print(f'Captured {observer.frames} frames; {observer.errors} reconstruction errors. '
              f'Queue: {output}', flush=True)
        return 1 if observer.errors else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list-interfaces', action='store_true')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--interface', help='Loopback or lab interface name from --list-interfaces')
    source.add_argument('--pcap', help='Import an existing PCAP/PCAPNG instead of capturing live')
    parser.add_argument('--port', type=int, default=9001)
    parser.add_argument('--output', default='captures/chat.jsonl')
    parser.add_argument('--pcap-out', help='Optionally also save original packets to a new PCAP')
    args = parser.parse_args(argv)
    if args.list_interfaces:
        try:
            list_interfaces()
            return 0
        except (ImportError, OSError) as error:
            print(f'Cannot list capture interfaces: {error}', file=sys.stderr)
            return 1
    if not args.interface and not args.pcap:
        parser.error('Choose --interface for live capture or --pcap for saved traffic')
    if args.pcap and args.pcap_out:
        parser.error('--pcap-out is only available for live capture')
    if not 1 <= args.port <= 65535:
        parser.error('--port must be in 1..65535')
    try:
        return capture(args)
    except KeyboardInterrupt:
        return 0
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        print(f'Capture error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
