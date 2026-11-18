"""Small-instance quantum order finding. No known order or factors in this path."""
import math
import multiprocessing as mp
import time
from collections import Counter


class AttackFailure(RuntimeError):
    pass


def _require_supported(modulus, base):
    if type(modulus) is int and modulus.bit_length() in (248, 2048) and type(base) is int and base == 5:
        from rsa_modes import simulator_resources
        resources = simulator_resources(modulus)
        raise AttackFailure(f'RSA-{modulus.bit_length()} exceeds local simulator capacity ({resources["total_qubits"]} qubits)')
    if type(modulus) is not int or type(base) is not int or (modulus, base) != (33, 5):
        raise ValueError('This simulator supports modulus 33 and base 5')


def controlled_multiplier(multiplier, modulus=33):
    """Local qubit 0 is control; qubits 1..6 encode the residue."""
    _require_supported(modulus, 5)
    import numpy as np
    if not 1 <= multiplier < modulus or math.gcd(multiplier, modulus) != 1:
        raise ValueError("Multiplier must be a coprime residue")
    matrix = np.zeros((128, 128), dtype=complex)
    for column in range(128):
        control, value = column & 1, column >> 1
        target = multiplier * value % modulus if control and value < modulus else value
        matrix[(target << 1) | control, column] = 1
    return matrix


def build_circuit(counting=12, modulus=33, base=5):
    _require_supported(modulus, base)
    from qiskit import QuantumCircuit
    circuit = QuantumCircuit(counting + 6, counting)
    circuit.x(counting)
    circuit.h(range(counting))
    for j in range(counting):
        circuit.unitary(controlled_multiplier(pow(base, 2**j, modulus), modulus),
                        [j, *range(counting, counting + 6)], label=f"CM{j}")
    # Inverse QFT including swaps; counting qubit j has weight 2**j.
    for j in range(counting // 2):
        circuit.swap(j, counting - j - 1)
    for j in range(counting):
        for k in range(j):
            circuit.cp(-math.pi / 2**(j-k), k, j)
        circuit.h(j)
    circuit.measure(range(counting), range(counting))
    return circuit


def convergents(numerator, denominator):
    p0, p1, q0, q1 = 0, 1, 1, 0
    while denominator:
        term, remainder = divmod(numerator, denominator)
        p0, p1 = p1, term * p1 + p0
        q0, q1 = q1, term * q1 + q0
        yield p1, q1
        numerator, denominator = denominator, remainder


def infer_factors(counts, counting=12, modulus=33, base=5):
    for bits, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        sample = int(bits, 2)
        if not sample:
            continue
        for numerator, order in convergents(sample, 2**counting):
            if order >= modulus:
                break
            if order < 2 or order % 2 or pow(base, order, modulus) != 1:
                continue
            x = pow(base, order // 2, modulus)
            p, q = math.gcd(x-1, modulus), math.gcd(x+1, modulus)
            if 1 < p < modulus and 1 < q < modulus and p*q == modulus:
                return {"factors": sorted([p, q]), "order": order,
                        "sample": bits, "phase": sample / 2**counting,
                        "convergent": [numerator, order], "sample_count": count}
    return None


def _worker(connection, seed, shots, batches, modulus=33, base=5):
    try:
        from qiskit_aer import AerSimulator
        circuit = build_circuit(modulus=modulus, base=base)
        simulator = AerSimulator(method="statevector", device="CPU",
                                 max_parallel_threads=1, fusion_enable=False)
        counts = Counter()
        for batch in range(batches):
            options = {} if seed is None else {"seed_simulator": seed + batch}
            result = simulator.run(circuit, shots=shots, **options).result()
            if not result.success:
                raise AttackFailure("Aer simulation failed")
            counts.update(result.get_counts())
            answer = infer_factors(counts, modulus=modulus, base=base)
            if answer:
                answer.update(counts=dict(counts), batches=batch+1,
                              shots=shots*(batch+1), seed=seed)
                connection.send((True, answer))
                return
        connection.send((False, "No useful measured order within retry budget"))
    except Exception as error:
        connection.send((False, f"Quantum simulation failed: {error}"))
    finally:
        connection.close()


def run_factorization(seed=None, shots=1024, batches=3, timeout=30.0, *, modulus=33, base=5):
    """Deadline includes child startup, imports, circuit preparation and simulation."""
    if shots < 1 or not 1 <= batches <= 3 or timeout <= 0:
        raise ValueError("Invalid simulation budget")
    _require_supported(modulus, base)
    started = time.perf_counter()
    context = mp.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(sender, seed, shots, batches, modulus, base))
    process.start()
    sender.close()
    try:
        remaining = max(0, timeout - (time.perf_counter()-started))
        if not receiver.poll(remaining):
            raise AttackFailure("Quantum attack timed out")
        try:
            success, payload = receiver.recv()
        except EOFError as error:
            raise AttackFailure("Quantum worker exited without a result") from error
        if not success:
            raise AttackFailure(payload)
        payload["elapsed_seconds"] = time.perf_counter()-started
        return payload
    finally:
        receiver.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join()


MAX_CRACK_BITS = 8


def general_multiplier(multiplier, modulus):
    """Controlled modular multiplication for any small modulus (qubit 0 is control)."""
    import numpy as np
    work = modulus.bit_length()
    size = 1 << (work + 1)
    matrix = np.zeros((size, size), dtype=complex)
    for column in range(size):
        control, value = column & 1, column >> 1
        target = multiplier * value % modulus if control and value < modulus else value
        matrix[(target << 1) | control, column] = 1
    return matrix


def general_circuit(modulus, base):
    """Same construction as build_circuit, sized for the modulus: 2n counting + n work qubits."""
    from qiskit import QuantumCircuit
    work = modulus.bit_length()
    counting = 2 * work
    circuit = QuantumCircuit(counting + work, counting)
    circuit.x(counting)
    circuit.h(range(counting))
    for j in range(counting):
        circuit.unitary(general_multiplier(pow(base, 2**j, modulus), modulus),
                        [j, *range(counting, counting + work)], label=f"CM{j}")
    for j in range(counting // 2):
        circuit.swap(j, counting - j - 1)
    for j in range(counting):
        for k in range(j):
            circuit.cp(-math.pi / 2**(j-k), k, j)
        circuit.h(j)
    circuit.measure(range(counting), range(counting))
    return circuit


def crack(modulus, *, seed=None, max_attempts=8, shots=1024, progress=None):
    """Factor a small odd modulus with simulated Shor order finding.

    Bases sharing a factor with the modulus are skipped, so every success comes
    from the quantum measurement, never from a lucky classical gcd.
    """
    import random
    if type(modulus) is not int or modulus % 2 == 0 or not 15 <= modulus < 1 << MAX_CRACK_BITS:
        raise ValueError(f'Shor simulation supports odd moduli from 15 to {(1 << MAX_CRACK_BITS) - 1}')
    from qiskit_aer import AerSimulator
    report = progress or (lambda message: None)
    rng = random.Random(seed)
    work = modulus.bit_length()
    counting = 2 * work
    simulator = AerSimulator(method="statevector", max_parallel_threads=0)
    started = time.perf_counter()
    tried = []
    candidates = [a for a in range(2, modulus - 1) if math.gcd(a, modulus) == 1]
    rng.shuffle(candidates)
    for base in candidates[:max_attempts]:
        tried.append(base)
        report(f'Attempt {len(tried)}: base a = {base}, simulating {counting + work} qubits ...')
        options = {} if seed is None else {"seed_simulator": seed + len(tried)}
        result = simulator.run(general_circuit(modulus, base), shots=shots, **options).result()
        if not result.success:
            raise AttackFailure("Aer simulation failed")
        counts = result.get_counts()
        answer = infer_factors(counts, counting=counting, modulus=modulus, base=base)
        if answer:
            answer.update(modulus=modulus, base=base, counts=counts, shots=shots,
                          counting_qubits=counting, work_qubits=work, attempts=len(tried),
                          bases_tried=tried, elapsed_seconds=time.perf_counter() - started)
            return answer
        report(f'Base {base} gave no usable period; trying another base.')
    raise AttackFailure(f'No factors after {len(tried)} bases')


if __name__ == "__main__":
    import json
    print(json.dumps(run_factorization(seed=0), indent=2))
