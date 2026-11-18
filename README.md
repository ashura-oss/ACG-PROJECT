# ACG — RSA Chat & Quantum Interceptor

## Desktop apps (live demo)

Two windowed apps replace the terminals for the presentation:

- **ACG Chat** (`chat_app.py`): open as many windows as you like. Each asks for a name and a lock:
  - **RSA (7-bit, crackable):** the AES-256 key is locked with a fresh random 7-bit RSA key, small enough for the Shor simulation to factor live.
  - **Post-quantum:** the AES-256 key comes from X25519 + ML-KEM-768.

  Windows find each other automatically, but only within the same lock. Click a name to start a chat. Messages are AES-256-GCM in both modes.
- **ACG Interceptor** (`interceptor_app.py`): passively captures loopback traffic on TCP ports 47100–47199 with Npcap, the driver Wireshark uses. Every conversation gets its own tab:
  - **RSA conversations:** **Run Shor's algorithm** factors N, rebuilds the private key, unlocks the AES key, then **Decrypt** shows the chat.
  - **Post-quantum conversations:** the attack has nothing to work on, so the messages stay encrypted.

  Each run also writes a `.pcap` under `captures/` that opens in Wireshark.

Start the Interceptor **before** the chatters start talking, because it needs to see each connection's handshake.

```powershell
.\.venv\Scripts\pythonw.exe interceptor_app.py
.\.venv\Scripts\pythonw.exe chat_app.py
```

Measured on a Core Ultra 7 laptop, the Shor simulation takes about 2 s for a 7-bit modulus (21 qubits) and about 70 s for 8 bits (24 qubits). Each extra bit is roughly 30 times slower, so the apps use 7 bits.

## Terminal version

Two-way encrypted terminal chat with a separate passive Interceptor. Alice and Bob communicate directly over TCP; Interceptor captures their traffic and queues messages for key recovery and decryption using a Qiskit Aer simulation of Shor's algorithm.

Run all three terminals on one laptop.

```text
Alice  <────── encrypted chat ──────>  Bob
                     │
               packet capture
                     │
                Interceptor
```

## Install

Use 64-bit Python 3.12 or newer. On Windows, install [Npcap](https://npcap.com/#download) for packet capture.

Clone the repository and install the dependencies in PowerShell:

```powershell
git clone https://github.com/ashura-oss/ACG-PROJECT.git
cd ACG-PROJECT
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-network.txt
```

Open three terminals in the same repository directory. The commands below use the virtual environment directly, so activation is optional.

On Linux/macOS, create the environment with `python3 -m venv .venv`, replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`, and use your loopback interface (`lo` on Linux, usually `lo0` on macOS).

## Choose the RSA mode

| Mode | Setup argument | Interceptor workflow |
| --- | --- | --- |
| RSA-2048 + OAEP-SHA256 (default) | `--bits 2048` | Capture and queue encrypted traffic |
| RSA-33 | `--bits 6` | Run Shor, recover the key, decrypt messages |
| 248-bit RSA | `--bits 248` | Capture traffic and measure chat operation timings |
| Hybrid X25519 + ML-KEM-768 | `--pqc` | Capture traffic; Shor has nothing to factor, so messages stay encrypted |

Use **RSA-33** for the complete quantum recovery demonstration. Local Shor recovery is available for RSA-33; the larger modes are for chat and timing comparisons.

### Post-quantum mode

Run the RSA-33 conversation first, then repeat it with a hybrid key to show the fix:

```powershell
.\.venv\Scripts\python.exe chat.py setup --pqc --key-file chat_keys_pqc.json
```

Start Bob with `--key-file chat_keys_pqc.json`; Alice needs no change. Alice makes a fresh X25519 key and an ML-KEM-768 ciphertext for each session, and both shared secrets feed one HKDF, so an attacker has to break both. When you press **F2** or **F3**, Interceptor marks the session `QUANTUM-SAFE` and leaves its messages queued.

Limits of this mode: Bob's key is a long-lived file rather than a fresh key per connection, and names are not authenticated, as in the RSA modes. It shows the key exchange, not a complete TLS 1.3 handshake.

## Start the chat

### 1. Create Bob's key

For RSA-2048:

```powershell
.\.venv\Scripts\python.exe chat.py setup --bits 2048 --key-file chat_keys_2048.json
```

Run setup once. It preserves existing files. To use RSA-33 instead, run:

```powershell
.\.venv\Scripts\python.exe chat.py setup --bits 6 --key-file chat_keys.json
```

Use the matching key filename in Bob's command below. Alice selects the mode automatically from Bob's public key.

### 2. Terminal C — Interceptor

List capture interfaces:

```powershell
.\.venv\Scripts\python.exe capture.py --list-interfaces
```

Select the loopback interface and start Interceptor **before connecting Alice**. On Windows with Npcap, the loopback interface is typically `\Device\NPF_Loopback`:

```powershell
.\.venv\Scripts\python.exe intercept.py --live --interface '\Device\NPF_Loopback' --port 9001 --capture captures/chat.jsonl
```

Wait for capture to start, then launch the peers.

### 3. Terminal B — Bob

```powershell
.\.venv\Scripts\python.exe chat.py listen --host 127.0.0.1 --port 9001 --name Bob --key-file chat_keys_2048.json
```

For RSA-33, replace `chat_keys_2048.json` with `chat_keys.json`.

### 4. Terminal A — Alice

```powershell
.\.venv\Scripts\python.exe chat.py connect --host 127.0.0.1 --port 9001 --name Alice
```

Type a message in either chat terminal and press Enter. Interceptor collects the encrypted traffic as the conversation runs.

## Chat controls

| Action | Key or command |
| --- | --- |
| Send a message | Enter |
| Clear the local conversation view | `/clear` |
| Disconnect | `/quit` or Ctrl+C |
| Scroll conversation history | PgUp / PgDn |
| Jump to latest messages | Ctrl+End |

Messages support Unicode and up to 4096 UTF-8 bytes per line. Add `--plain` to either chat command for scrolling text output.

To start another conversation, rerun Bob's listening command and reconnect Alice. Keep Interceptor running to capture the next session.

## Use Interceptor

With an RSA-33 conversation running:

1. Send messages from both Alice and Bob. They appear in Interceptor's queue.
2. Press **F2** to run Shor and recover the RSA key.
3. Press **F3** to decrypt the queued messages.
4. Press **F4** to toggle automatic processing of new messages.

You can also type commands in the command bar:

| Command | Action |
| --- | --- |
| `status` | Refresh sessions and queue counts |
| `recover` | Recover keys for captured RSA-33 sessions |
| `decrypt-all` | Recover keys as needed and decrypt the backlog |
| `follow` / `unfollow` | Start or pause automatic processing |
| `export transcripts/conversation.jsonl` | Save decrypted messages to a new file |
| `help` | Show available commands |
| `quit` | Close Interceptor |

Use Tab to select a pane and PgUp/PgDn to scroll. Closing Interceptor leaves Alice and Bob connected. Captures are saved under `captures/`; exported conversations go to the path you specify.

To reopen a saved capture:

```powershell
.\.venv\Scripts\python.exe intercept.py --capture captures/chat.jsonl
```

To process it and exit:

```powershell
.\.venv\Scripts\python.exe intercept.py --capture captures/chat.jsonl --decrypt-all
```

## Timings and tests

Measure RSA-2048 key generation, session exchange, and message encryption/decryption:

```powershell
.\.venv\Scripts\python.exe benchmark_rsa.py --bits 2048 --trials 20
```

Use `--bits 248` for the 248-bit profile. Results are saved as `rsa2048_benchmark_report.json` or `rsa248_benchmark_report.json`.

Run the RSA-33 Shor benchmark and the test suite:

```powershell
.\.venv\Scripts\python.exe benchmark.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

To include live packet-capture tests on Windows:

```powershell
$env:ACG_LIVE_CAPTURE_INTERFACE = '\Device\NPF_Loopback'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
Remove-Item Env:ACG_LIVE_CAPTURE_INTERFACE
```

## Single-terminal workflow

The original menu is also available:

```powershell
.\.venv\Scripts\python.exe main.py
```

Select **1** to encrypt a message, **2** to run Shor and copy the recovered AES key, then **3** to paste that key and decrypt. Select **4** to exit.

## More details

- [Network setup and packet-capture guide](NETWORK_DEMO.md)
- [RSA-2048 setup and timings](RSA2048.md)
- [248-bit RSA timings](RSA248_TIMINGS.md)
- [Test results](VALIDATION.md)
