"""Measure 248-bit chat operations; report simulator infeasibility separately."""
import argparse
from importlib.metadata import version
import json
from pathlib import Path
import platform
import statistics
import time

from chat_protocol import create_session, decrypt_record, encrypt_record, recover_master
from rsa_modes import generate_key, simulator_resources
from shor import AttackFailure, run_factorization


def summary(samples):
    ordered = sorted(samples)
    return {'trials': len(samples), 'median_ms': statistics.median(samples) * 1000,
            'min_ms': ordered[0] * 1000, 'max_ms': ordered[-1] * 1000,
            'p95_ms': ordered[min(len(ordered)-1, int(len(ordered)*0.95))] * 1000}


def measure(trials=20):
    samples = {name: [] for name in ('key_generation', 'session_wrap', 'session_unwrap',
                                    'encrypt_message_4096_bytes', 'decrypt_message_4096_bytes')}
    for _ in range(trials):
        started = time.perf_counter()
        key = generate_key(248)
        samples['key_generation'].append(time.perf_counter() - started)
        started = time.perf_counter()
        header, master = create_session('Alice', 'Bob', public_key=(key['N'], key['e']))
        samples['session_wrap'].append(time.perf_counter() - started)
        started = time.perf_counter()
        recovered = recover_master(header, key['d'])
        samples['session_unwrap'].append(time.perf_counter() - started)
        if recovered != master:
            raise RuntimeError('Session secret failed round-trip validation')
        for sequence in range(25):
            started = time.perf_counter()
            record = encrypt_record(header, master, 'a_to_b', sequence, 'x' * 4096)
            samples['encrypt_message_4096_bytes'].append(time.perf_counter() - started)
            started = time.perf_counter()
            message = decrypt_record(header, recovered, record)
            samples['decrypt_message_4096_bytes'].append(time.perf_counter() - started)
            if message != 'x' * 4096:
                raise RuntimeError('Authenticated message failed round-trip validation')
    resources = simulator_resources(key['N'])
    try:
        run_factorization(modulus=key['N'], base=5)
    except AttackFailure as error:
        reason = str(error)
    else:
        raise RuntimeError('248-bit resource preflight did not reject this simulator layout')
    return {'python': platform.python_version(), 'platform': platform.platform(),
            'versions': {name: version(name) for name in ('cryptography', 'pycryptodome', 'qiskit', 'qiskit-aer')},
            'rsa_bits': key['N'].bit_length(), 'public_modulus': key['N'], 'public_exponent': key['e'],
            'session_seed_bits': 128, 'operation_roundtrips_passed': True,
            'timings': {name: summary(rows) for name, rows in samples.items()},
            'quantum_attack': {'status': 'not_run_resource_limit', 'execution_seconds': None,
                               'reason': reason, 'layout_projection': resources,
                               'note': 'Extending this dense-matrix/statevector layout; not a bound for every Shor implementation.'}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trials', type=int, default=20)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('rsa248_benchmark_report.json'))
    args = parser.parse_args(argv)
    if not 1 <= args.trials <= 100:
        parser.error('--trials must be in 1..100')
    report = measure(args.trials)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    for name, result in report['timings'].items():
        print(f'{name}: median {result["median_ms"]:.4f} ms ({result["trials"]} trials)')
    print('Shor attack: not run; local simulator resource limit.')
    print('Report:', args.output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
