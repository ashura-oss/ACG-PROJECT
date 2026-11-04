"""RSA parameter profiles for the chat's two experimental sizes."""
import math
import secrets

E248 = 65537


def validate_public(modulus, exponent):
    if type(modulus) is not int or type(exponent) is not int:
        raise ValueError('RSA parameters must be integers')
    if (modulus, exponent) == (33, 3):
        return 1
    if modulus.bit_length() == 248 and modulus % 2 and exponent == E248:
        return 2
    raise ValueError('Supported modes: RSA-33 and 248-bit RSA')


def generate_key(bits=248):
    if type(bits) is not int:
        raise ValueError('RSA size must be an integer')
    if bits == 6:
        return {'N': 33, 'e': 3, 'd': 7}
    if bits != 248:
        raise ValueError('Supported RSA sizes: 6 and 248 bits')
    from Crypto.Util.number import getPrime
    while True:
        p, q = getPrime(124), getPrime(124)
        modulus = p * q
        phi = (p - 1) * (q - 1)
        if p != q and modulus.bit_length() == bits and math.gcd(E248, phi) == 1:
            return {'N': modulus, 'e': E248, 'd': pow(E248, -1, phi)}


def validate_private(key):
    if type(key) is not dict or set(key) != {'N', 'e', 'd'}:
        raise ValueError('Invalid RSA key fields')
    version = validate_public(key['N'], key['e'])
    if type(key['d']) is not int or not 1 <= key['d'] < key['N']:
        raise ValueError('Invalid RSA private exponent')
    probes = range(33) if version == 1 else [0, 1, 2, 3, 255, *[secrets.randbelow(key['N']) for _ in range(8)]]
    if any(pow(pow(value, key['e'], key['N']), key['d'], key['N']) != value for value in probes):
        raise ValueError('Invalid RSA private key')
    return key


def simulator_resources(modulus):
    if type(modulus) is not int or modulus < 2:
        raise ValueError('Invalid modulus')
    work = (modulus - 1).bit_length()
    counting = 2 * work
    return {'work_qubits': work, 'counting_qubits': counting,
            'total_qubits': work + counting,
            'statevector_bytes': 16 * (1 << (work + counting)),
            'controlled_matrix_bytes': 16 * (1 << (2 * (work + 1)))}
