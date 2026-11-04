"""Small-instance quantum order finding. No known order or factors in this path."""
import math
import multiprocessing as mp
import time
from collections import Counter


class AttackFailure(RuntimeError):
    pass


def controlled_multiplier(multiplier, modulus=33):
    """Local qubit 0 is control; qubits 1..6 encode the residue."""
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
    if type(modulus) is not int or type(base) is not int or (modulus, base) != (33, 5):
        raise ValueError("This prototype supports only modulus 33 and base 5")
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


if __name__ == "__main__":
    import json
    print(json.dumps(run_factorization(seed=0), indent=2))
