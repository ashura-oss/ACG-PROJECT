"""Compatibility entry point for the 248-bit RSA benchmark."""
from benchmark_rsa import main as benchmark_main, measure as benchmark_measure


def measure(trials=20):
    return benchmark_measure(trials, bits=248)


def main(argv=None):
    return benchmark_main(argv, default_bits=248)


if __name__ == '__main__':
    raise SystemExit(main())
