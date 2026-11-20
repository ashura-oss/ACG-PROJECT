"""Shor's algorithm, simulated with Qiskit Aer, for small RSA moduli (up to 8 bits).

Uses 2n counting qubits and n work qubits for an n-bit modulus. Bases that share
a factor with N are skipped, so every factor comes from the quantum measurement.
"""
import math
import random
import time


def _multiplier(a, n):
    """Controlled 'multiply by a mod n' as a permutation matrix (qubit 0 is the control)."""
    import numpy as np
    size = 1 << (n.bit_length() + 1)
    matrix = np.zeros((size, size))
    for column in range(size):
        control, value = column & 1, column >> 1
        target = a * value % n if control and value < n else value
        matrix[(target << 1) | control, column] = 1
    return matrix


def circuit(n, a):
    from qiskit import QuantumCircuit
    work = n.bit_length()
    count = 2 * work
    qc = QuantumCircuit(count + work, count)
    qc.x(count)                         # work register starts at 1
    qc.h(range(count))                  # counting register in superposition
    for j in range(count):              # controlled a^(2^j) mod n
        qc.unitary(_multiplier(pow(a, 2 ** j, n), n), [j, *range(count, count + work)])
    for j in range(count // 2):         # inverse quantum Fourier transform
        qc.swap(j, count - j - 1)
    for j in range(count):
        for k in range(j):
            qc.cp(-math.pi / 2 ** (j - k), k, j)
        qc.h(j)
    qc.measure(range(count), range(count))
    return qc


def _fractions(y, q):
    """Continued-fraction convergents of y/q, as (numerator, denominator)."""
    p0, p1, q0, q1 = 0, 1, 1, 0
    while q:
        t, r = divmod(y, q)
        p0, p1, q0, q1 = p1, t * p1 + p0, q1, t * q1 + q0
        yield p1, q1
        y, q = q, r


def _factors_from(counts, n, a, count):
    for bits, _ in sorted(counts.items(), key=lambda kv: -kv[1]):
        y = int(bits, 2)
        for _, r in _fractions(y, 2 ** count) if y else ():
            if r >= n:
                break
            if r % 2 or pow(a, r, n) != 1:
                continue
            half = pow(a, r // 2, n)
            p, q = math.gcd(half - 1, n), math.gcd(half + 1, n)
            if 1 < p < n and p * q == n:
                return {'y': y, 'r': r, 'half': half, 'factors': sorted((p, q))}
    return None


def crack(n, seed=None):
    """Factor n with simulated Shor order finding. Returns the evidence."""
    if type(n) is not int or n % 2 == 0 or not 15 <= n < 256:
        raise ValueError('Supports odd N from 15 to 255')
    from qiskit_aer import AerSimulator
    rng, simulator, started = random.Random(seed), AerSimulator(method='statevector'), time.perf_counter()
    bases = [a for a in range(2, n - 1) if math.gcd(a, n) == 1]
    rng.shuffle(bases)
    count = 2 * n.bit_length()
    for a in bases[:8]:
        result = simulator.run(circuit(n, a), shots=1024, seed_simulator=rng.randrange(1 << 30)).result()
        found = _factors_from(result.get_counts(), n, a, count)
        if found:
            return {**found, 'n': n, 'a': a, 'qubits': 3 * n.bit_length(),
                    'seconds': time.perf_counter() - started}
    raise RuntimeError('No factors found; try again')
