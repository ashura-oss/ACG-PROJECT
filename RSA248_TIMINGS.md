# 248-bit RSA timing mode

The chat supports two profiles: the existing RSA-33 exchange and a new profile
with a freshly generated **248-bit modulus**, two independent 124-bit probable
primes, and public exponent 65537. Alice reads the public parameters from Bob's
greeting; neither the UI nor the message framing needs a manual modulus value.

Create a separate receiver key and start Bob with it:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-network.txt
.\.venv\Scripts\python.exe chat.py setup --bits 248 --key-file chat_keys_248.json
.\.venv\Scripts\python.exe chat.py listen --key-file chat_keys_248.json --name Bob
```

Start Alice and Interceptor using the commands in `NETWORK_DEMO.md`. Alice
automatically negotiates the 248-bit profile. Existing captures and RSA-33 keys
remain supported. The original menu/package application remains RSA-33.

The version-2 exchange wraps a random 128-bit seed as one textbook-RSA block
and derives the 32-byte session master with HKDF-SHA256. A 248-bit modulus is
only 31 bytes, so a complete 32-byte AES key cannot fit as one RSA integer, and
standard SHA-256 OAEP padding cannot fit either. This profile is a small RSA
experiment, not RSA-OAEP. HKDF expands the seed; it does not create extra entropy.
The two directional AES-GCM keys and record authentication operate as before.

## Reproduce the measurements

```powershell
.\.venv\Scripts\python.exe benchmark_rsa248.py --trials 20
```

The report records measured key generation, session wrapping/unwrapping, and
4,096-byte message processing. Each trial verifies the actual round trip.
The JSON report contains public parameters and timings, never private exponents
or session secrets. It measures Python/application work, not network latency.

## Quantum timing boundary

There is **no measured Shor attack time for the 248-bit profile**. Its report
uses `quantum_attack.status = "not_run_resource_limit"` and a null execution
time. Interceptor reports the resource limit and leaves these messages queued.
It neither substitutes classical factorization nor uses Bob's private exponent.

Extending this particular implementation's register sizing would use 248 work
qubits and 496 counting qubits: 744 total. A double-precision statevector would
require `16 * 2^744 = 2^748` bytes. Each dense controlled-multiplier matrix would
require `16 * (2^249)^2 = 2^502` bytes. These are layout projections, not a lower
bound for all quantum factoring implementations. Requests are rejected before
matrix allocation or simulator startup. Small RSA-33 simulations still run.

References: [Aer statevector memory](https://qiskit.github.io/qiskit-aer/stubs/qiskit_aer.AerSimulator.html),
[PyCryptodome prime generation](https://www.pycryptodome.org/src/util/util#Crypto.Util.number.getPrime).
