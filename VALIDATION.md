# Network-mode validation

## Interceptor dashboard validation

The complete suite passed **74 tests in 20.529 seconds**, with live Npcap capture
enabled. Interceptor's dashboard was rendered at 80×24 and 120×36 and verified
to retain its queue, traffic, evidence and command controls. Its headless
integration test executed real Shor recovery, displayed only authenticated
messages, preserved a typed command during recovery, followed newly appended
traffic, and rejected a tampered message. Controller tests also verified that
submitting commands stays responsive while recovery runs and that closing the
dashboard does not stop a separately owned packet collector.

## Current full-screen UI validation

The complete updated suite passed **64 tests in 16.401 seconds**, with live
Npcap capture explicitly enabled. This includes actual passive packet capture
and quantum recovery, the full-screen UI wired to real encrypted sockets,
Unicode draft preservation during incoming messages, rejected-input editing,
scrolling, local display clearing, offline history, and narrow-screen headers.

The UI uses prompt_toolkit 3.0.53. The original protocol, RSA-33 key exchange,
and `shor.py` circuit are unchanged.

Validated on 4 November 2026 using 64-bit Python 3.12.14 on Windows.

## Automated result

The initial implementation run of `python -m unittest discover -s tests -v`
passed **54 tests** in 10.759 seconds. This is the historical result before the
chat-interface changes and optional live-capture test described below; it is not
an updated count for the expanded suite.

- The original application and quantum tests continue to pass.
- Independent Alice/Bob processes exchanged real TCP messages in both directions,
  including Unicode; rejected oversized input without losing the connection; and
  exited cleanly on `/quit`.
- Synthetic PCAP fixtures exercised actual packet parsing and reconstruction of
  split/coalesced frames, out-of-order data, retransmissions, and both directions.
  A fresh attacker process then ran actual Qiskit Aer order finding and decrypted
  those messages using only the exported public capture.
- A separate integration test ran Shor once and recovered additional independently
  keyed sessions appended later. Authentication failures released no plaintext,
  did not advance sequence counters, and remained visible in queue status.
- Packet reconstruction tests cover sequence wrap, FIN arriving before data,
  missing segments, conflicting overlaps, IPv6, Ethernet padding, capture snapshot
  truncation, malformed frames and capture begun after the TCP handshake.
- Queue tests cover incomplete JSONL writes, replay/gaps, malformed metadata,
  missing handshakes, bounded quantum failure, exclusive transcript export, and
  capture continuing while key recovery is running.

## Quantum feasibility

The original 20-seed benchmark passed **20/20** with wall times **1.539–1.896
seconds** (mean **1.616 seconds**). All runs recovered order 10 and factors 3 and
11 from circuit-generated measurements. Full evidence is in
`network_benchmark_report.json`.

The benchmark was run using an isolated copy of the unchanged original benchmark
and `shor.py`; the original `benchmark_report.json` remains the historical report.
These timings measure quantum recovery, not packet-capture startup or a quantum
speed advantage. They are not a guarantee for another host or a VM.

Test environment: cryptography 50.0.2, NumPy 2.3.5, Qiskit 2.6.1, Qiskit Aer
0.18.2, Scapy 2.8.0.

## Live Windows packet-capture check

After Npcap was installed, the opt-in test
`test_optional_live_capture_quantum_recovery_and_independent_chat` passed on
4 November 2026 in **3.203 seconds**, with
`ACG_LIVE_CAPTURE_INTERFACE=\Device\NPF_Loopback`.

This test started the actual passive `capture.py` process before connecting
independent Alice/Bob subprocesses on a temporary ephemeral port. It captured
their real packets, reconstructed the public handshake and encrypted messages,
and ran a fresh `intercept.py` process with the real Qiskit Aer Shor simulation.
Both directions' messages authenticated and decrypted. The test then stopped
the capture process and verified that both chat peers continued exchanging
messages while the capture file remained unchanged. No synthetic packets,
forwarding relay, endpoint-key input to the attacker, or automatic privilege
elevation were used in this check.

A subsequent focused run of all four network integration tests, with live
capture explicitly enabled, passed in **8.898 seconds**. This includes actual
bidirectional chat, the live capture/recovery/observer-stop check, synthetic
PCAP reconstruction and fresh-process quantum recovery, and one quantum run
reused across newly appended sessions. It does not replace the historical
full-suite count above.

This establishes live capture for this host's tested configuration, not every
driver or OS. The earlier pre-Npcap check also verified that a missing driver
produced an explicit prerequisite error. Run the three-terminal rehearsal on
the presentation machine and optionally enable the live test as documented in
`NETWORK_DEMO.md`.
