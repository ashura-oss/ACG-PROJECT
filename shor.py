"""Shor's algorithm on a simulated quantum computer (Qiskit Aer), for small N."""
import math
import random
import time
from fractions import Fraction

import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


def multiply(a, n, bits):
    """Gate: if the control qubit is 1, multiply the work register by a (mod n)."""
    size = 2 ** (bits + 1)
    gate = np.zeros((size, size))
    for i in range(size):
        control, x = i & 1, i >> 1
        y = a * x % n if control and x < n else x
        gate[(y << 1) | control, i] = 1
    return gate


def find_period(a, n):
    """The quantum part: measure a multiple of 1/r, where r is the period of a^x mod n."""
    bits = n.bit_length()
    count = 2 * bits
    qc = QuantumCircuit(count + bits, count)
    qc.x(count)                                   # work register = 1
    qc.h(range(count))                            # counting register: every x at once
    for j in range(count):
        qc.unitary(multiply(pow(a, 2 ** j, n), n, bits), [j, *range(count, count + bits)])
    qc.compose(inverse_qft(count), range(count), inplace=True)
    qc.measure(range(count), range(count))
    counts = AerSimulator().run(qc, shots=256).result().get_counts()
    for measured in sorted(counts, key=counts.get, reverse=True):
        r = Fraction(int(measured, 2), 2 ** count).limit_denominator(n).denominator
        for guess in range(r, n, r):              # the fraction may give a divisor of r; try its multiples
            if pow(a, guess, n) == 1:
                return guess
    return None


def inverse_qft(count):
    qc = QuantumCircuit(count)
    for j in range(count // 2):
        qc.swap(j, count - j - 1)
    for j in range(count):
        for k in range(j):
            qc.cp(-math.pi / 2 ** (j - k), k, j)
        qc.h(j)
    return qc


def crack(n):
    """Factor n: pick a random a, find its period r quantumly, then gcd(a^(r/2) ± 1, n)."""
    start = time.time()
    while True:
        a = random.randrange(2, n - 1)
        if math.gcd(a, n) != 1:
            continue                              # skip lucky guesses: the factors must come from Shor's
        r = find_period(a, n)
        if r and r % 2 == 0:
            p = math.gcd(pow(a, r // 2, n) - 1, n)
            if 1 < p < n:
                return {'factors': (p, n // p), 'a': a, 'r': r, 'seconds': time.time() - start}


if __name__ == '__main__':                        # python shor.py 91  ->  prints the result as JSON
    import json
    import sys
    print(json.dumps(crack(int(sys.argv[1]))))
