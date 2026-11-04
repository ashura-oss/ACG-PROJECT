"""Key recovery from public package and quantum-derived factors only."""
import math
from package_io import load_package, validate_package
from shor import run_factorization
from toy_rsa import unwrap_key


def recover_key(package, factors):
    validate_package(package)
    if len(factors) != 2:
        raise ValueError('Expected two recovered factors')
    p, q = factors
    modulus, exponent = package['header']['N'], package['header']['e']
    if any(type(value) is not int or not 1 < value < modulus for value in factors) or p*q != modulus or math.gcd(p, q) != 1:
        raise ValueError('Invalid recovered factors')
    private_exponent = pow(exponent, -1, (p-1)*(q-1))
    return unwrap_key(package['header']['wrapped_key_digits'], private_exponent), private_exponent


def attack_package(package, seed=None):
    validate_package(package)
    evidence = run_factorization(seed=seed, modulus=package['header']['N'], base=5)
    key, private_exponent = recover_key(package, evidence['factors'])
    return key, private_exponent, evidence


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Recover a candidate key from only a public package')
    parser.add_argument('package')
    parser.add_argument('--seed', type=int, default=None)
    args = parser.parse_args()
    key, exponent, evidence = attack_package(load_package(args.package), seed=args.seed)
    print(json.dumps({'candidate_key_hex': key.hex(), 'private_exponent': exponent, 'evidence': evidence}))
