# Passive RSA-33 chat demonstration

`chat.py setup` now defaults to RSA-2048. This rehearsal explicitly selects
`--bits 6` for the original RSA-33 quantum recovery. For RSA-2048 setup and
measured timings, see [RSA2048.md](RSA2048.md); Interceptor captures that profile
but cannot recover its key with the local simulator.

Two terminal processes exchange AES-256-GCM encrypted messages over a direct TCP connection. A third process passively captures the traffic, reconstructs application frames, and queues them. The observer runs the existing Qiskit Aer Shor simulation to recover RSA factors, reconstructs the private exponent, unwraps each captured session secret, and authenticates/decrypts the queued messages.

```text
Alice (chat.py connect) <----- encrypted TCP -----> Bob (chat.py listen)
                                 |
                         loopback packet capture
                                 |
                       capture.py -> capture JSONL
                                 |
                    intercept.py -> Shor -> transcript
```

The observer does not forward traffic. Closing it does not interrupt the chat. One laptop and three terminals are sufficient; VMs and separate laptops are optional.

## Install

Use 64-bit Python 3.12 or newer. In the repository directory on Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-network.txt
```

On Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-network.txt
```

The network requirements permit compatible releases. The original `requirements.txt` preserves the pins for the original benchmark environment. Record the installed versions and rerun the benchmark before presenting on another machine. Chat-only machines can install `requirements-chat.txt` instead.

Windows live capture requires [Npcap](https://npcap.com/guide/npcap-users-guide.html), installed separately. Installing a Python package does not install its kernel driver. Npcap supports loopback capture; the obsolete legacy loopback adapter option is not needed by modern packet-capture tools. Capture permissions depend on how Npcap was installed. On Linux use the loopback interface `lo` and the capture privileges required by the OS; on macOS this is usually `lo0`. Do not assume a fixed Windows interface index.

## Three-terminal rehearsal on one laptop

All paths below are relative to the repository directory. Each terminal must use the same repository and virtual environment.

First prepare Bob's legitimate endpoint key:

```powershell
.\.venv\Scripts\python.exe chat.py setup --bits 6 --key-file chat_keys.json
```

This endpoint-only file contains the intentionally tiny RSA private key. The observer does not read it, and it must not be added to Git.

**Terminal C: start passive capture before the connection handshake.** List interfaces, choose the loopback capture interface shown by the command, then start the observer:

```powershell
.\.venv\Scripts\python.exe capture.py --list-interfaces
.\.venv\Scripts\python.exe intercept.py --capture captures/chat.jsonl --live --interface "<loopback interface from the list>" --port 9001
```

Wait for the capture-ready message before connecting Alice. If capture initialization fails, resolve the reported driver/interface/permission issue first. The observer runs capture in a separate process so packets continue to be recorded during quantum simulation.

**Terminal B: start Bob.**

```powershell
.\.venv\Scripts\python.exe chat.py listen --host 127.0.0.1 --port 9001 --name Bob --key-file chat_keys.json
```

**Terminal A: connect Alice directly to Bob.**

```powershell
.\.venv\Scripts\python.exe chat.py connect --host 127.0.0.1 --port 9001 --name Alice
```

Type messages in either chat terminal. Use `/quit` to close the connection. A new connection gets a fresh session secret; restart the listening command if necessary to begin the next session. For Linux/macOS substitute `.venv/bin/python` and the appropriate loopback interface in the same commands.

## Chat interface

Interactive chat terminals use a full-screen view with a conversation history, connection status, and a separate message composer. Incoming messages do not overwrite the text being typed. Press Enter to send, use `/clear` to clear the local display, and `/quit` to disconnect. Clearing the display does not delete captured traffic or change encryption state. After a remote disconnect, the conversation stays visible with an offline status until you quit.

PgUp/PgDn scroll the conversation while keeping the composer focused; Ctrl+End returns to the latest messages. Ctrl+C also exits. Invalid input stays in the composer for editing.

When input or output is redirected, the peers use a plain line-oriented interface for scripts and logs. Add `--plain` to either the `listen` or `connect` command to choose that interface explicitly. Both interfaces use the same protocol and commands. Educational explanations and limitations are kept in this document so the chat screen can focus on the conversation.

## Interceptor dashboard

Terminal C is **Interceptor**, a dedicated dashboard in an interactive terminal. It separates capture status and session counts, quantum recovery evidence, authenticated conversation text, and a command bar. Packet capture and key recovery run outside the UI event loop, so the dashboard can redraw and preserve an unfinished command during Shor simulation.

Use F2 to recover keys, F3 to decrypt the queued messages, and F4 to toggle follow mode. Ctrl+C or `quit` exits the dashboard. The command bar also accepts:

```text
status
recover
decrypt-all
follow
```

`status` refreshes the captured-session queue. `recover` executes quantum order finding and displays its measurement evidence; recovered session secrets remain candidates until an AES-GCM tag verifies. `decrypt-all` recovers keys if needed and authenticates the backlog. `follow` enables live processing of incoming messages; `unfollow` pauses it, and F4 toggles between them. `export transcripts/conversation.jsonl` saves authenticated plaintext records, and `quit` stops the observer and any capture process it started. The chat peers continue independently.

Add `--plain` to `intercept.py` to use the line-oriented command prompt instead, or redirect input/output to select it automatically. In plain mode, `follow` runs until Ctrl+C returns to the prompt; Ctrl+C outside follow mode exits. Noninteractive `--decrypt-all` and `--follow` remain available for scripts.

An RSA private exponent recovered from measurements is reused for later sessions with the same public key. Each session still has its own secret and directional traffic keys. Shor is not rerun for each message. If quantum recovery fails, sessions remain queued and the error is reported; there is no classical factorization fallback.

For a noninteractive recovery of an existing capture:

```powershell
.\.venv\Scripts\python.exe intercept.py --capture captures/chat.jsonl --decrypt-all
```

## Saved packet captures

The capture importer can reconstruct messages from a PCAP/PCAPNG recorded with a packet-capture tool:

```powershell
.\.venv\Scripts\python.exe capture.py --pcap captures/chat.pcapng --port 9001 --output captures/imported.jsonl
.\.venv\Scripts\python.exe intercept.py --capture captures/imported.jsonl --decrypt-all
```

Start packet capture before session establishment and capture both directions with full packet lengths. If the wrapped-secret handshake is missing, later ciphertext alone is insufficient for this recovery flow. Truncated, malformed, or incomplete streams must be treated as incomplete evidence. TCP can split one application frame across packets, coalesce frames, retransmit bytes, and deliver packets out of order; reconstruction must account for those cases. See [Wireshark's TCP reassembly documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection).

Captures and exported transcripts are local artifacts, ignored by Git in `captures/` and `transcripts/`. An export intentionally contains recovered plaintext; it is not a public encrypted package.

## Protocol and teaching boundaries

- This is the custom `ACG-CHAT` version-1 protocol over TCP, not HTTPS/TLS.
- Bob sends only public RSA parameters and a display name. Alice sends a random session ID, public names/algorithms, and 64 toy-RSA-wrapped base-33 digits representing a fresh 32-byte session secret.
- HKDF-SHA256 derives different AES-256-GCM keys for the two directions. A per-direction sequence number determines a 12-byte nonce. The session header, direction, and sequence number are authenticated along with each message. Receivers reject replayed or out-of-order application records.
- Wire frames are bounded newline-delimited JSON. Messages are single-line UTF-8, at most 4,096 encoded bytes. Display names are labels, not authenticated identities; this first version models passive eavesdropping.
- Only successfully authenticated plaintext is shown or exported. A valid-looking key is not proof of correct decryption. Packet-capture gaps, malformed records, and authentication failures must remain visible.
- `shor.py` is the original bounded 18-qubit circuit simulation: 12 counting qubits and six work qubits. Measured phases drive continued fractions, order validation, and factor extraction. The observer has no input for an endpoint private key or a sender secret.
- The endpoint legitimately starts with the toy RSA private key. Its setup constant is not an attack result. The attacker derives its exponent from simulation-produced factors.
- RSA-33 is trivial to factor classically; the deterministic 33-digit wrapping also permits a public reverse lookup. This demo uses the quantum-factorization route to show the mechanism, not its necessity.
- Qiskit Aer executes on a classical CPU. Neither the simulated attack nor localhost networking demonstrates quantum speed advantage, scalable modular arithmetic, or a practical break of RSA-2048. AES itself is not broken.

## Verification

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe benchmark.py
```

The tests distinguish actual TCP chat subprocesses from synthetic packet fixtures used to exercise the importer. Synthetic packets are a reproducible parser/recovery test, not proof that live capture works on a particular driver or interface. Run the three-terminal rehearsal on the presentation machine to validate its live capture setup. The existing benchmark measures quantum feasibility only, and does not include network-capture startup.

An optional live integration test captures real loopback traffic, runs quantum recovery, and verifies that the chat continues after the observer exits. It is skipped unless `ACG_LIVE_CAPTURE_INTERFACE` is explicitly set. On Windows, after confirming the actual loopback interface with `capture.py --list-interfaces`:

```powershell
$env:ACG_LIVE_CAPTURE_INTERFACE = '\Device\NPF_Loopback'
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_network_integration.py -k optional_live -v
Remove-Item Env:ACG_LIVE_CAPTURE_INTERFACE
```

The test uses a temporary ephemeral port, not the live demo's port 9001. It does not install drivers or elevate privileges. On Linux/macOS set the same environment variable to the appropriate loopback interface before invoking the test.

The initial implementation run passed **54 tests** and the separate quantum gate passed **20/20 seeds**, with measured recovery wall times **1.539–1.896 seconds** on the development machine. Live Windows loopback capture and recovery were subsequently verified using Npcap. See [VALIDATION.md](VALIDATION.md) and [network_benchmark_report.json](network_benchmark_report.json) for evidence and the distinction between historical suite results and live capture checks.

For the seminar, show the queue before recovery, actual quantum measurement evidence, authenticated recovered messages in both directions, and continued chat after stopping the observer. Cite sources and declare AI assistance as required by the assignment.
