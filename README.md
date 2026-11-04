# Connected RSA-33 demonstration

Local Python CLI for an educational chain: AES-256-GCM encryption, toy RSA key protection, simulated quantum factorization, candidate AES-key recovery, and manual authenticated decryption.

The [network chat demonstration](NETWORK_DEMO.md) adds two-way terminal chat and a separate **passive packet-capture and decryption tool**. Alice and Bob connect directly over TCP on one laptop; the observer records packets, queues encrypted messages, runs the existing Shor simulation, and decrypts the captured conversation. No relay or shared endpoint-secret file is used by the observer. The original menu demonstration below remains available.

## Setup and launch

Tested with 64-bit Python 3.14 on Windows. From this directory in PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

Create the local `.venv` using the commands above; it is not included in the repository. No IBM account or quantum hardware is required. The active package is `encrypted_package.json` beside `main.py`, regardless of the terminal's current directory.

## Rehearsal

1. Select **1**, enter a short message such as `Hello 🔐`, and inspect the public package output. The sender does not print its AES key.
2. Select **2**. Inspect real Aer measurement counts, the accepted phase and order, recovered factors, and reconstructed private exponent. Copy the candidate key's 64 hex characters.
3. Select **3** and paste the key. Only successful AES-GCM authentication reveals the plaintext.
4. Select **3** again with a different valid 64-character hex key to show authentication failure.
5. Select **4** to exit.

Messages are a single line, including empty input, at most 4,096 UTF-8 bytes. Creating another package asks before replacement. Missing or malformed packages return an error. Quantum failure returns to the menu without a key; it never substitutes classical factorization.

## Quantum implementation and evidence

Six work qubits start at `|1⟩`; 12 counting qubits undergo phase estimation followed by an inverse QFT. Each seven-qubit controlled unitary permutes residues using powers computed from public `N=33`, `a=5`, with identity action on work-register states 33 through 63. Aer executes these matrices directly on a CPU statevector. Elementary-gate synthesis is intentionally outside this small-instance prototype.

Measured phases supply continued-fraction denominators, validated by modular exponentiation and GCD processing. Zero and unusable phases are rejected. The circuit builder and attack do not use known factors, a known order, exhaustive order search, or classical factorization. There are 1,024 shots per batch and at most three batches. A child process bounds circuit preparation, simulation, and recovery to a 30-second deadline.

Run the reproducible feasibility gate:

```powershell
.\.venv\Scripts\python.exe benchmark.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

`benchmark_report.json` records all 20 seeds, machine information, dependency versions, measurements, timings, and the pass result. It is a measured benchmark of this machine, not a guarantee for another laptop. Re-run it before presenting elsewhere. The gate requires at least 19 successes and all runs under 30 seconds.

Initial result on 4 November 2026: **20/20 successful**, with wall times **4.49 to 5.57 seconds**, using Qiskit 2.6.1 and Aer 0.18.2. All recovered order 10 and factors 3 and 11 from measured data. The application test suite covers the connected workflow, all byte values, package validation, authentication failures, process isolation of inputs, retry exhaustion, and timeout termination.

## Package and authentication

The version-1 JSON object has `header`, `nonce_hex`, and `ciphertext_and_tag_hex`. The header identifies `AES-256-GCM`, `TOY-RSA`, `BASE33-PAIRS-32-BYTES`, public `N` and `e`, and 64 wrapped key digits. Its sorted, compact ASCII JSON serialization is AES-GCM associated data. The 12-byte nonce and ciphertext with appended 16-byte tag are hex encoded. Strict parsing rejects unsupported fields, duplicate keys, wrong types, and invalid lengths.

Option 2 returns a **candidate** key, without authenticating AES or decrypting data. Option 3 exclusively reads a user-entered key, accepts upper/lowercase hex and surrounding whitespace, and rejects internal whitespace. Authentication failures reveal no plaintext. Sender state is unnecessary for recovery, as verified in a fresh process; the menu is not an isolated security boundary.

## Limits and claims

RSA-33 is trivially insecure. Its deterministic per-digit encoding can also be reversed by publicly encrypting all 33 possible digits, without factoring. This application demonstrates a factorization-based recovery route, not its necessity. It is not RSA-OAEP, a practical attack on RSA-2048, scalable modular arithmetic, or evidence of quantum speed advantage. AES is real library-backed AES-GCM; the weak toy key protection makes the whole construction insecure. Manual key entry serves the teaching flow and adds no security. ML-KEM is outside scope.

References: [IBM Shor tutorial](https://quantum.cloud.ibm.com/docs/en/tutorials/shors-algorithm), [Aer simulator](https://qiskit.github.io/qiskit-aer/stubs/qiskit_aer.AerSimulator.html), [cryptography AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/), [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).

For assessment, cite the sources used and declare AI assistance as required by the assignment brief. Present only results you can explain and independently verify.
