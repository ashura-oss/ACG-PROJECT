import time
import unittest
from unittest.mock import patch

import numpy as np
from shor import (AttackFailure, _worker, build_circuit, controlled_multiplier,
                  infer_factors, run_factorization)


class QuantumTests(unittest.TestCase):
    def test_permutations(self):
        for multiplier in {pow(5, 2**j, 33) for j in range(12)}:
            matrix = controlled_multiplier(multiplier)
            np.testing.assert_array_equal(matrix.sum(axis=0), np.ones(128))
            np.testing.assert_array_equal(matrix.sum(axis=1), np.ones(128))
            for x in range(64):
                for control in (0, 1):
                    column = 2*x+control
                    expected = multiplier*x % 33 if control and x < 33 else x
                    self.assertEqual(np.argmax(matrix[:, column]), 2*expected+control)

    def test_initialization_and_phase(self):
        from qiskit.quantum_info import Statevector
        circuit = build_circuit(counting=4)
        prefix = circuit.copy_empty_like()
        prefix.append(circuit.data[0].operation, [4])
        state = Statevector.from_instruction(prefix)
        self.assertEqual(np.argmax(abs(state.data)), 1 << 4)
        answer = infer_factors({format(round(4096/10), '012b'): 100})
        self.assertEqual(answer['order'], 10)
        self.assertEqual(answer['factors'], [3, 11])
        self.assertIsNone(infer_factors({'000000000000': 100}))
        self.assertIsNone(infer_factors({'100000000000': 100}))

    def test_timeout(self):
        started = time.perf_counter()
        with self.assertRaisesRegex(AttackFailure, 'timed out'):
            run_factorization(timeout=0.001)
        self.assertLess(time.perf_counter()-started, 3)

    def test_public_parameter_boundary(self):
        for modulus, base in ((15, 2), (33, 2), (33.0, 5)):
            with self.assertRaises(ValueError):
                run_factorization(modulus=modulus, base=base)

    def test_exhausted_batches(self):
        class Result:
            success = True
            def result(self): return self
            def get_counts(self): return {'000000000000': 1024}
        class Connection:
            payload = None
            def send(self, payload): self.payload = payload
            def close(self): pass
        connection = Connection()
        with patch('qiskit_aer.AerSimulator.run', return_value=Result()) as run:
            _worker(connection, 0, 1024, 3)
        self.assertEqual(run.call_count, 3)
        self.assertFalse(connection.payload[0])
        self.assertIn('retry budget', connection.payload[1])


if __name__ == '__main__':
    unittest.main()
