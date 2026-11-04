"""Educational textbook RSA arithmetic, deliberately insecure."""
N, E = 33, 3


def encode_key(key):
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes")
    return [digit for byte in key for digit in divmod(byte, N)]


def decode_key(digits):
    if len(digits) != 64 or any(type(x) is not int or not 0 <= x < N for x in digits):
        raise ValueError("Expected 64 base-33 digits")
    values = [N*digits[i]+digits[i+1] for i in range(0, 64, 2)]
    if any(value > 255 for value in values):
        raise ValueError("Recovered digit pair does not represent a byte")
    return bytes(values)


def wrap_key(key):
    return [pow(digit, E, N) for digit in encode_key(key)]


def unwrap_key(digits, private_exponent):
    return decode_key([pow(digit, private_exponent, N) for digit in digits])
