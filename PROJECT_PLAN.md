# ACG CA1 Final Project Plan

## Quantum-Assisted Toy RSA Key Recovery with AES-GCM and Manual Command-Line Decryption

**Project type:** Interactive Python command-line demonstration  
**Intended audience:** ST2504 Applied Cryptography classmates  
**Chosen design:** Fully connected demonstration (Option A)  
**Status:** Design decisions agreed on 4 November 2026; implementation has not started. Shor order-finding for `N = 33` is the first feasibility gate and must be tested before it can be presented as a working result.

### Agreed scope

- Build one connected RSA-33 attack demonstration, including AES-key recovery and manual AES-GCM decryption.
- Use permutation-based modular multiplication constructed from public inputs. The assignment does not explicitly require an elementary-gate arithmetic implementation.
- Quantum measurements must drive order recovery. No known-order shortcut, exhaustive classical order search, or classical factorization fallback is permitted in the attack path.
- Keep the existing `pqc_quantum_demo` project separate. ML-KEM is outside this prototype's scope.
- A disconnected factor-15 demonstration would change the agreed scope and requires discussion before adoption.

---

## 1. Project Goal

Demonstrate, using a deliberately tiny RSA instance and a locally simulated quantum circuit, how recovering the factors of an RSA modulus can reveal an AES key that protects a message.

The audience should see this sequence:

1. A user types a plaintext message into the command line.
2. The program converts the message into UTF-8 bytes.
3. The program generates a random 256-bit AES key and encrypts the message with **AES-256-GCM**.
4. The program protects that AES key using **educational textbook RSA with a tiny modulus**, and exports an intercepted-data package.
5. The user chooses to run the quantum attack. **Qiskit Aer** simulates Shor's quantum order-finding step against the *same RSA modulus* used to protect the AES key.
6. Classical processing recovers the prime factors, reconstructs the private RSA exponent, and uses it to recover the 32-byte AES key.
7. The program **prints the recovered AES key in hexadecimal** and returns to the main menu. **No message decryption occurs automatically.**
8. The user chooses the manual decryption option, **copies and pastes** the recovered 64-character hexadecimal AES key into the command line, and initiates AES-GCM decryption.
9. The program verifies the AES-GCM authentication tag and displays the original plaintext only if decryption succeeds.

**Demonstration's core claim:** If an RSA scheme protecting an AES key is compromised, an attacker may recover that AES key and decrypt the data it protects. The program illustrates the mathematical attack chain; it does **not** demonstrate breaking real RSA-2048 or a useful quantum speed advantage.

---

## 2. Why This Design

This is **Option A**, a connected attack, rather than Option B, two independent demonstrations.

| Aspect | Chosen Option A | Alternative Option B |
|---|---|---|
| AES encryption | Real AES-GCM | Real AES-GCM |
| RSA use | Toy RSA protects the actual AES key | Production-style RSA-OAEP encrypts an AES key in a separate example |
| Shor simulation | Targets the **same toy RSA modulus** used for key protection | Factors a different toy integer |
| Recovered factors | Used to recover the AES key used by the message | Do not decrypt the protected message |
| Final AES decryption | **Manual key entry in the CLI** | Separate encryption demonstration |
| Fidelity to deployed cryptography | Only the AES layer is production-grade | Encryption architecture can use production-grade algorithms |
| Educational value | One continuous causal chain | More realistic encryption alongside separate quantum teaching |

The user-facing distinction: **the simulated quantum result must contribute to key recovery**, not merely be displayed beside unrelated encryption.

---

## 3. Threat Model and Learning Objectives

### Scenario

A sender encrypts a user-supplied message using a randomly generated AES-256 key and makes an encrypted package available. An attacker sees the public RSA parameters and encrypted package, but does not receive the original plaintext, the AES key, RSA private exponent, or prime factors.

This is a separation of function inputs and responsibilities within an educational application, not process or memory isolation. The presenter supplied the plaintext, and the sender temporarily held its AES key. A fresh-process recovery test must demonstrate that the attack needs only the exported package.

### The intercepted package contains

- RSA public modulus `N` and public exponent `e`.
- Toy-RSA-encrypted AES-key digits.
- AES-GCM nonce.
- AES-GCM ciphertext followed by its 16-byte authentication tag, stored as one hex field.
- Versioned, nonsecret metadata identifying the algorithms and encoding, authenticated as described below.

### Intended learning objectives

- Understand that plaintext strings become bytes before encryption.
- Understand **hybrid encryption**: AES protects message data; RSA protects an AES key.
- Distinguish public-key material from secret-key material.
- Explain that **Shor's algorithm factors the public RSA modulus; it does not directly decrypt AES or RSA ciphertext**.
- Show how recovered prime factors allow reconstruction of an RSA private exponent.
- Show that possession of the correct AES key enables AES-GCM decryption.
- Explain the gap between a toy quantum simulation and breaking a cryptographic-size RSA key.

---

## 4. Technology and Cryptographic Parameters

### Environment

- Python 3, run locally in a terminal or VS Code integrated terminal.
- IBM's **Qiskit** for quantum circuit construction.
- **Qiskit Aer** for local, classical simulation of the quantum circuit.
- Python `cryptography` package for AES-GCM.
- Python built-in `pow(message, exponent, modulus)` for toy RSA arithmetic.
- Optional `matplotlib` for a circuit visualization or measurement histogram.

Suggested installation:

```bash
python -m pip install cryptography qiskit qiskit-aer numpy matplotlib
```

### AES layer

| Parameter | Design |
|---|---|
| Algorithm | AES-256-GCM |
| Key | Fresh, random **32 bytes** per encryption |
| Nonce | **12 bytes**, never reused with the same key |
| Input | Single-line UTF-8 message, including empty input, up to 4 KiB after encoding |
| Output | Ciphertext followed by the 16-byte authentication tag |
| Associated data | Deterministically serialized public package header |
| Decryption key input | **Manually entered** 64-character hexadecimal AES key |

The original AES key should **not be printed during sender encryption** and should not be embedded in the exported package. Decryption must verify the authentication tag before displaying plaintext.

### Toy RSA layer

| Parameter | Value |
|---|---|
| Prime `p` | `3` |
| Prime `q` | `11` |
| Public modulus `N = pq` | `33` |
| Euler totient `φ(N) = (p - 1)(q - 1)` | `20` |
| Public exponent `e` | `3` |
| Private exponent `d = e⁻¹ mod 20` | `7` |
| Public key | `(N=33, e=3)` |
| Private key | `(N=33, d=7)` |

Textbook operations:

```text
Encrypt: c = m^3 mod 33
Decrypt: m = c^7 mod 33
```

These values are selected solely because they make the arithmetic manageable and provide different public and private exponents. **RSA-33 is completely insecure**: it can be factored or brute-forced instantly with classical computation. Shor is included to demonstrate a quantum *method*, not because it is needed to defeat RSA-33.

### Encoding an AES key for toy RSA

Each AES key byte ranges from 0 to 255, while a textbook RSA message integer must satisfy `0 <= m < 33`. Encode every byte as **two base-33 digits**:

```text
high = byte // 33
low  = byte % 33
byte = 33 * high + low
```

For example:

```text
Byte: 72
Base-33 digits: [2, 6]
Toy RSA encryption: [2^3 mod 33, 6^3 mod 33] = [8, 18]
Toy RSA decryption: [8^7 mod 33, 18^7 mod 33] = [2, 6]
Reconstructed byte: 33 * 2 + 6 = 72
```

Thus a **32-byte AES key becomes 64 toy-RSA plaintext digits and then 64 toy-RSA ciphertext integers**. After decryption, pair the recovered digits to reconstruct each byte and verify that each reconstructed value lies in `0..255`.

This deterministic per-digit mechanism is **not RSA-OAEP and not secure key wrapping**. It cannot be substituted for real hybrid encryption in a practical system.

In particular, anyone can encrypt all 33 possible digits with the public key and build a reverse lookup table that recovers every wrapped digit without factoring `N`. The demonstration illustrates a factorization-based recovery route; factorization is not necessary to defeat this toy encoding. The lookup attack is explanatory context, not a fallback implementation.

### Package format and authentication

Use a versioned JSON object with exactly three top-level fields: `header`, `nonce_hex`, and `ciphertext_and_tag_hex`.

The `header` contains these fields:

| Field | Required value or format |
|---|---|
| `version` | Integer `1` |
| `aes_algorithm` | `AES-256-GCM` |
| `rsa_algorithm` | `TOY-RSA` |
| `key_encoding` | `BASE33-PAIRS-32-BYTES` |
| `N` | Integer `33` |
| `e` | Integer `3` |
| `wrapped_key_digits` | Array of exactly 64 integers, each in `0..32` |

Serialize the header for AES-GCM associated data with Python `json.dumps(header, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')`. Construct the header after RSA wrapping and before AES encryption. Reconstruct exactly these associated-data bytes during manual decryption. Header fields remain public but are covered by the AES-GCM authentication check.

Generate a random 12-byte nonce and store it as 24 lowercase hex characters. Store ciphertext and appended tag as lowercase hex; decoded length must be at least 16 bytes and no more than 4 KiB plus 16 bytes. Reject unknown versions, algorithms, fields, missing fields, duplicate JSON keys, invalid hex, invalid lengths, and wrong value types before simulation or decryption. JSON booleans must not be accepted as integers. Only the fixed RSA parameters are supported by this prototype.

Malformed packages produce a package-validation error. Structurally valid changes to authenticated fields, ciphertext, nonce, or tag must fail AES-GCM authentication. The attack alone does not authenticate the package.

---

## 5. Full Command-Line Workflow

### Main menu

```text
=======================================
 QUANTUM RSA ATTACK DEMONSTRATION
=======================================
[1] Encrypt Message
[2] Run Shor / Recover AES Key
[3] Decrypt Message (Manual AES Key)
[4] Exit
=======================================
Select option: _
```

### Option 1: Sender encryption

1. Ask the user to enter a single-line plaintext string, for example `HELLO WORLD`. Accept empty input and reject messages exceeding 4 KiB of UTF-8 bytes.
2. Convert it to UTF-8 bytes.
3. Generate a fresh, random AES-256 key.
4. Encode the AES key as 64 base-33 digits.
5. Encrypt these 64 digits using the toy RSA **public key** and construct the public header.
6. Encrypt the message using AES-GCM with a fresh nonce and the serialized header as associated data.
7. Export the specified package as `encrypted_package.json`. Maintain one active package and ask before replacing an existing file; declining preserves it.
8. Show the AES ciphertext, RSA-encrypted AES-key digits, and public key. **Do not show the raw AES key.**
9. Return to the main menu.

Illustrative CLI output, with placeholders rather than fabricated random values:

```text
--- ENCRYPT MESSAGE ---
Enter plaintext: HELLO WORLD

[+] UTF-8 encoding complete
[+] AES-256-GCM encryption successful
[+] Toy RSA key protection complete

RSA public key: N=33, e=3
AES ciphertext: <hex>
Encrypted AES key: <64 integers>

[+] Saved encrypted_package.json
Press Enter to return to menu...
```

### Option 2: Attacker's simulated quantum attack

1. Load `encrypted_package.json` without reading sender-private secrets.
2. Extract the RSA public key `(N=33, e=3)` and the encrypted AES-key digits.
3. Execute the **Qiskit Aer Shor order-finding simulation** for modulus 33 using fixed base `a = 5` and bounded resampling.
4. Use measurement data and classical continued-fraction/order validation to obtain a successful order; **do not hard-code the order or factors as the attack result**.
5. Apply classical GCD post-processing to obtain nontrivial factors `3` and `11`.
6. Reconstruct `φ(33)=20` and private exponent `d=7`.
7. Decrypt the 64 encrypted key digits with toy RSA.
8. Reassemble all 32 AES key bytes.
9. Display the **64-character hexadecimal candidate recovered AES key**, with a clear prompt to copy it. AES authentication has not yet been checked.
10. Return to the main menu. **Do not call AES decryption, print plaintext, or automatically prefill the decryption function.**

Illustrative successful output, contingent on a working Qiskit implementation:

```text
--- SHOR / RECOVER AES KEY ---
Target RSA modulus: 33
Selected base: 5
[+] Executing quantum simulation ...
[+] Valid order obtained: r=10
[+] Factors recovered: 3 and 11
[+] Reconstructed RSA private exponent: d=7
[+] RSA-protected AES key decrypted

CANDIDATE RECOVERED AES-256 KEY (HEX):
<64 hexadecimal characters>

AES-GCM authentication will be checked in option [3].
Copy the key above, then select option [3].
Press Enter to return to menu...
```

**Security and demonstration rule:** The displayed AES key must come from toy RSA decryption using the recovered private exponent, not from a sender-side variable. The plaintext must remain undisclosed at this stage.

Show actual measurement counts or their most frequent outcomes, inferred phases, and the accepted order so the audience can inspect the evidence. If bounded retries fail, report failure and return to the menu without printing a key or substituting a classical answer.

### Option 3: Manual AES decryption

1. Load the AES-GCM ciphertext, nonce and tag from the intercepted package.
2. Prompt the user to **type or paste the recovered AES key**.
3. Trim surrounding whitespace, accept uppercase or lowercase hex, then require exactly **64 hexadecimal characters** with no internal whitespace; decode to exactly 32 bytes.
4. Attempt AES-GCM decryption with the serialized public header as associated data and verify the authentication tag.
5. Only if authentication succeeds, decode the result as UTF-8 and display the plaintext.
6. On an incorrect key or altered package, show a generic decryption/authentication failure; do not output unauthenticated plaintext.

Illustrative CLI interaction:

```text
--- MANUAL AES DECRYPTION ---
Enter recovered AES-256 key (64 hex characters):
> <user pastes recovered key>

[+] Key format valid
[+] AES-GCM authentication successful

RECOVERED PLAINTEXT:
HELLO WORLD

Press Enter to return to menu...
```

**No automation of the last step:** Option 2 must not invoke Option 3 or silently transfer its recovered key into decryption. The manual act of entering the key is the intended interaction. This manual step is pedagogical; it does not itself provide additional cryptographic security.

Missing files and malformed packages produce concise errors and return to the menu. Charts are optional; all essential evidence and interactions must work in the terminal.

---

## 6. Shor's Algorithm: Exact Mathematical Example

For the proposed modulus `N = 33`, choose `a = 5`, which is coprime to 33.

The *order* is the least positive integer `r` for which:

```text
5^r mod 33 = 1
```

For this example, a correct order is `r = 10`. On a successful run, the **quantum circuit's measurements**, not a hard-coded return value, must provide information enabling the classical program to infer and validate this order.

Then:

```text
x = 5^(r/2) mod 33
  = 5^5 mod 33
  = 23

p = gcd(x - 1, 33) = gcd(22, 33) = 11
q = gcd(x + 1, 33) = gcd(24, 33) = 3
```

Finally:

```text
φ(33) = (3 - 1)(11 - 1) = 20
d = 3^(-1) mod 20 = 7
```

**Quantum vs. classical separation:** Quantum order finding generates samples from which a period can be deduced. Continued fractions, order checking, GCD factor extraction, private-exponent calculation and RSA decryption are **classical** operations. Shor's algorithm does not directly decrypt AES.

### Agreed quantum implementation

- Use a work register of **6 qubits**, initialized to `|1⟩`. It represents states `0..63`, of which `0..32` encode residues modulo 33.
- Start with a **12-qubit counting register** as an exploratory design; register size and resource requirements may need revision.
- Construct permutation-based controlled modular multiplication using only public `N=33`, `a=5`, and powers `b = pow(a, 2**j, N)`. For each multiplier, map `|x⟩` to `|b*x mod N⟩` for `0 <= x < N`, and leave `N <= x < 64` unchanged. Since `b` is coprime to `N`, this defines a reversible permutation on the entire work register.
- Verify each permutation is bijective and test Qiskit's bit ordering. Do not construct gates using known factors, a precomputed order, or a precomputed orbit period.
- Perform quantum phase estimation and an inverse quantum Fourier transform.
- Measure the counting register.
- Derive candidate orders from measured phases through continued fractions and validate them by modular exponentiation. Reject zero phases and unusable candidates. Do not scan all possible orders or factors; any combination of sample-derived denominators must have an explicit bound and retain its measurement provenance.
- Initially use 1,024 shots per batch and at most three batches per attack, with fixed base 5. These are feasibility settings to verify, not evidence of reliability. Record any justified adjustments before integration.
- Reject trivial/invalid factors and verify `p*q == N`.

Permutation matrices are acceptable for this small educational simulation. Decomposition into a scalable elementary-gate modular-arithmetic circuit is outside scope. Do not describe this implementation as scalable quantum arithmetic.

### Feasibility acceptance gate

- Obtain actual Aer measurement data supporting valid factor recovery for 33.
- Achieve successful factor recovery in at least 19 of 20 independent runs within the configured retry budget. Record simulator seeds for reproducibility; do not select only successful seeds.
- Complete every benchmark attack within 30 seconds on the presentation laptop, including circuit construction, transpilation, simulation, and classical processing after application startup.
- Bound wall-clock execution as well as retry count. A timeout reports failure and returns control to the menu; interrupt a running simulation when necessary.
- Record package versions, machine details, shot counts, retry settings, success counts, and timings. Pin tested dependencies in `requirements.txt` after the gate passes.

These are acceptance targets, not measured results. If targets cannot be met, review the design before building the full application.

**Open implementation risk:** IBM's familiar introductory Shor circuit targets `N = 15`; it **cannot be reused unchanged** for `N = 33`. The `N = 33` circuit must be adapted and actually tested in Qiskit Aer. Building generic modular arithmetic or using controlled permutation-based modular multiplication can be resource-intensive. A proposed qubit count is **not** evidence that the simulation will be efficient or reliable.

A credible presentation must show actual circuit-derived measurement data, not hard-code `r=10`, `p=3`, or `q=11` in the simulated attack path.

---

## 7. Project File Layout

```text
quantum_rsa_demo/
├── main.py                  # Main CLI menu
├── sender.py                # UTF-8, AES-GCM, toy-RSA wrapping
├── toy_rsa.py               # Key arithmetic and base-33 encoding
├── shor.py                  # Qiskit circuits, measurements, factor extraction
├── attacker.py              # Reconstruct RSA key and recover AES key
├── decrypt.py               # Manual AES-key prompt and AES-GCM decryption
├── encrypted_package.json   # Public data and intercepted ciphertext only
├── requirements.txt
├── README.md
└── tests/
    ├── test_encoding.py
    ├── test_toy_rsa.py
    ├── test_aes.py
    ├── test_shor.py
    └── test_integration.py
```

### Separation rules

- `sender.py` may generate and temporarily hold the AES key, but it must **not save that key in `encrypted_package.json`**.
- The sender needs only `(N=33, e=3)` and must not calculate or retain `p`, `q`, or `d`. The mathematical constants in this document are explanatory examples, not attack outputs.
- `attacker.py` receives only the intercepted package and quantum factorization output.
- `decrypt.py` obtains the key only through a user-entered CLI string and loads the public AES-GCM ciphertext package. It must **not pull a recovered AES key directly from `attacker.py`**.
- The application may keep the intercepted encrypted package between menu selections, but must not silently expose secret values across the attacker/decryption boundary.

---

## 8. Testing and Acceptance Criteria

### Encryption tests

- Encrypt/decrypt standard UTF-8 messages such as `HELLO`, `Agent007!`, and `Hello 🔐` using the known AES key in a **unit test**.
- Verify that ciphertext, nonce and tag are saved correctly.
- Confirm no cleartext AES key is written to the intercepted package.
- Test empty input, Unicode, the 4 KiB byte limit, and package replacement cancellation.
- Validate the exact package schema, including rejection of duplicate keys, booleans in integer fields, unsupported parameters, and malformed data.
- Confirm that structurally valid tampering with header fields, nonce, ciphertext, or tag fails manual AES-GCM authentication.

### Toy RSA tests

- Test every possible byte value `0..255` through base-33 encoding and decoding.
- Validate the 64-integer wrapped-key length for a 32-byte AES key.
- Check that toy RSA encryption followed by toy RSA decryption recovers every digit.

### Quantum tests

- Produce actual measurement output from Qiskit Aer for modulus 33.
- Infer and validate a useful order via classical post-processing.
- Recover factors 3 and 11 from measured data, and verify the factors.
- Handle failed trials without falsely claiming a successful quantum run.
- Confirm the attack code does not return known factors directly as a shortcut.
- Verify full-register permutation correctness, work-register initialization, and phase-bit interpretation.
- Confirm gates do not depend on known factors or order and classical processing does not perform exhaustive order search or factorization.
- Reject zero or unusable phase samples and verify exhausted retries and timeouts return explicit failure without a fabricated key.
- Run the 20-run reliability and timing benchmark defined in Section 6.

### Manual-decryption tests

- If the user skips the Shor menu, Option 3 must still **ask for an AES key** instead of silently using any internal value.
- A correctly formatted but wrong key must fail authentication.
- Short, long, or nonhexadecimal input must be rejected before decryption.
- A correct manually entered recovered key must reveal the original plaintext.
- Option 2 must **never automatically decrypt or display the original message**.
- Verify uppercase hex and surrounding whitespace are accepted while internal whitespace is rejected.
- In a fresh process, recover a candidate key from only the exported package; then manually supply it to the decryption path. No sender state may be required.

### End-to-end pass condition

Starting with only the public/intercepted package, the simulated attack produces factors, the program reconstructs the RSA private exponent, the RSA-wrapped AES key is recovered and displayed, and **only after the user manually pastes that key in Option 3** does the CLI reveal the original message.

---

## 9. Recommended Development Order

| Milestone | Build | Success criterion |
|---|---|---|
| 1. Quantum feasibility | `shor.py` | Actual Aer measurements support factoring 33; reliability, runtime, and failure-handling targets pass |
| 2. Toy RSA and byte encoding | `toy_rsa.py` | All 256 byte values round-trip |
| 3. Sender and package | `sender.py`, AES-GCM | Versioned package and authenticated header work; secret AES key absent |
| 4. Manual decryption | `decrypt.py`, CLI option 3 | Correct pasted key decrypts, wrong key and tampering fail |
| 5. Key recovery | `attacker.py` | Reconstructed RSA exponent recovers AES key from package |
| 6. Integration | `main.py` | All three menu actions operate as specified |
| 7. Rehearsal | Terminal script and visuals | Repeatable outcome and clear explanation of limitations |

**Primary feasibility gate:** Milestone 1. Resolve quantum order-finding for modulus 33 before building the full CLI. The other components use standard Python cryptographic operations.

### Contingency

The connected RSA-33 attack is mandatory under the agreed scope. If its circuit cannot satisfy the feasibility gate, report the evidence and revisit the design with the user. Do not fake output, silently use classical factorization, or substitute a disconnected factor-15 demonstration. A disconnected fallback requires an explicit scope change. ML-KEM remains outside this prototype.

---

## 10. Presentation and Teaching Plan

The CA1 brief calls for a **30-minute seminar**, with about **20 minutes of presentation including the demonstration**, and **at least five minutes of Q&A/quiz with at least five questions**. Allocate the remaining time to transitions and questions as needed.

Suggested content flow:

1. **Problem and motivation:** RSA, AES and the quantum factoring threat.
2. **Hybrid encryption:** Why AES encrypts the message and RSA protects the AES key.
3. **Threat model:** Show exactly what the attacker knows and does not know.
4. **RSA mathematics:** Public exponent, modulus, factorization and private exponent.
5. **Shor mechanism:** Explain order finding and classical GCD processing.
6. **Live CLI demonstration:** Encrypt, simulate Shor, display recovered key, manually paste key to decrypt.
7. **Critical limitations:** Toy RSA, no OAEP, easy classical factoring, locally simulated quantum circuit.
8. **Risk assessment and real-world response:** Quantum-resistant public-key migration, sound key management, AES nonce management.
9. **At least five quiz/Q&A questions.**

### Possible quiz questions

1. Why does this program use AES for the message instead of encrypting the entire message with RSA?
2. What information is present in an RSA public key?
3. What problem does Shor's algorithm solve in this attack?
4. Why does knowing the factors of the RSA modulus allow the attacker to reconstruct a private exponent?
5. Does the quantum simulation break AES directly?
6. Does factoring 33 demonstrate that present-day quantum computers can break RSA-2048? Why not?

### Sample risk assessment

These ratings are **illustrative** and must be justified for a defined system and time horizon.

| Threat | Security goal | Likelihood | Impact | Recommended countermeasure |
|---|---|---|---|---|
| Future quantum attacker factors a real RSA modulus | Confidentiality | Low today for strong RSA; may change | High | Migrate to standardized post-quantum key establishment / key encapsulation |
| Adversary records RSA-protected secrets for later decryption | Confidentiality | Scenario-dependent | High | Plan for harvest-now-decrypt-later; prefer quantum-resistant key establishment for long-lived secrets |
| AES-GCM nonce reused with the same key | Confidentiality and integrity | Low if implemented properly | High | Enforce nonce uniqueness and use reviewed libraries |

---

## 11. Limitations and Claims to Avoid

**Accurate statements:**

- This program uses **real AES-GCM** to encrypt an actual user-entered message.
- It uses **toy textbook RSA-33** to encode and encrypt AES-key digits.
- If implemented successfully, Qiskit Aer **simulates** a quantum order-finding circuit for the same modulus used by toy RSA.
- The recovered RSA factors are used to derive a private exponent and recover the AES key.
- The user **manually enters** the recovered AES key to decrypt the AES-GCM ciphertext.

**Do not claim:**

- That RSA-33 provides meaningful encryption security.
- That quantum computation is required to factor 33 or to break this toy RSA scheme. In fact, the scheme can be broken trivially using classical methods.
- That splitting AES-key bytes and encrypting each base-33 digit is equivalent to secure RSA-OAEP key wrapping.
- That factorization is necessary to recover this toy wrapped key; a public 33-entry reverse lookup also defeats it.
- That the permutation-matrix construction demonstrates scalable quantum modular arithmetic.
- That Option 2 authenticates the recovered key or package; AES-GCM authentication occurs only in Option 3.
- That local classical simulation demonstrates a practical quantum speed advantage.
- That a successful factorization of 33 proves real-world RSA-2048 can be factored with currently available quantum computers.
- That Shor's algorithm itself decrypts AES or that the user's manual key entry adds cryptographic security.

**Specific real-world nuance:** Real RSA-based hybrid encryption would typically use RSA-OAEP with a sufficiently large RSA modulus to protect a symmetric key. TLS 1.3 does not use RSA key transport. The described demonstration is a teaching model for a vulnerable RSA-based key-protection architecture, **not a reenactment of modern TLS 1.3 traffic decryption**.

---

## 12. References and Next Verification Steps

Start with primary sources and verify current API syntax and library compatibility before coding:

- IBM Quantum, **Shor's Algorithm Tutorial**: https://quantum.cloud.ibm.com/docs/en/tutorials/shors-algorithm
- Qiskit Aer documentation: https://qiskit.github.io/qiskit-aer/
- Python `cryptography`, **Authenticated encryption / AESGCM**: https://cryptography.io/en/latest/hazmat/primitives/aead/
- NIST, **FIPS 197: Advanced Encryption Standard**: https://csrc.nist.gov/pubs/fips/197/final
- NIST, **SP 800-38D: Galois/Counter Mode (GCM)**: https://csrc.nist.gov/pubs/sp/800/38/d/final
- IETF, **RFC 8017: PKCS #1 RSA Cryptography Specifications**: https://www.rfc-editor.org/rfc/rfc8017
- IETF, **RFC 8446: TLS 1.3**: https://www.rfc-editor.org/rfc/rfc8446

For CA1, cite the actual sources used on slides and include a Harvard-style bibliography and a GenAI-use declaration as required by the assignment brief.

---

## 13. Final Definition of Done

The final deliverable is one local Python **command-line application** in which:

- A user can enter single-line UTF-8 plaintext, including empty input, up to 4 KiB after encoding.
- AES-256-GCM encrypts it under a random key.
- Toy RSA-33 protects that AES key using explicitly educational encoding.
- A Qiskit Aer Shor simulation **genuinely contributes factorization results** for the modulus used by the toy RSA scheme.
- The program reconstructs the toy RSA private exponent and prints the **recovered AES key in hex**.
- **Decryption is not automatic:** the application returns to the menu, and the user must select the manual decryption option and paste the recovered key.
- AES-GCM authentication is checked before any recovered plaintext is shown.
- The versioned public header is authenticated as associated data, and malformed packages are rejected before simulation or decryption.
- Quantum measurements drive recovery without known-order shortcuts or classical factorization fallback, and the recorded feasibility benchmark passes.
- Fresh-process recovery works from the exported package alone; Option 2 presents a candidate key without claiming AES authentication.
- The presenter accurately explains both the connected attack and why it is not a practical break of production-grade RSA.

**Final emphasis:** *Simulated quantum factorization → toy RSA private-key reconstruction → AES-key recovery → user manually enters the AES key → authenticated plaintext decryption.*
