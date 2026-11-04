# Network-mode validation

Validated on 4 November 2026 using 64-bit Python 3.12.14 on Windows.

## Automated result

`python -m unittest discover -s tests -v`: **54 tests passed** in 10.759 seconds.

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

## Remaining presentation-machine check

**Live Windows packet capture was not verified here:** this environment does not
have the Npcap driver or an administrator token. The live command was checked to
fail with an explicit Npcap prerequisite error instead of claiming capture was
running. Offline reconstruction tests do not establish working live capture.

After installing Npcap on the presentation laptop, follow `NETWORK_DEMO.md`:
select the loopback interface, wait for `Capture ready`, start the chat, recover
and decrypt both directions, and stop the observer while the chat continues.
