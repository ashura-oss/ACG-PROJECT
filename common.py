"""AES messages and the two ways of locking the AES key."""
import json
import math
import os
import random

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Messages: AES-256-GCM
def encrypt(key, text):
    nonce = os.urandom(12)
    return (nonce + AESGCM(key).encrypt(nonce, text.encode(), None)).hex()


def decrypt(key, blob):
    data = bytes.fromhex(blob)
    return AESGCM(key).decrypt(data[:12], data[12:], None).decode()


# Lock 1: RSA with a random 7-bit N, small enough for Shor's
def rsa_keys():
    primes = [p for p in range(3, 128) if all(p % k for k in range(2, p))]
    p, q = random.choice([(p, q) for p in primes for q in primes if p < q and 64 <= p * q < 128])
    phi = (p - 1) * (q - 1)
    e = random.choice([e for e in range(3, phi) if math.gcd(e, phi) == 1 and pow(e, -1, phi) != e])
    return p * q, e, pow(e, -1, phi)                    # N, e, d


def rsa_lock(aes_key, n, e):
    """N is tiny, so write the AES key in base N and RSA-encrypt each digit."""
    x, digits = int.from_bytes(aes_key, 'big'), []
    while x:
        x, digit = divmod(x, n)
        digits.append(digit)
    return [pow(digit, e, n) for digit in digits]


def rsa_unlock(locked, n, d):
    x = 0
    for c in reversed(locked):
        x = x * n + pow(c, d, n)
    return x.to_bytes(32, 'big')


# Lock 2: ML-KEM-768 (post-quantum)
def pqc_keys():
    return MLKEM768PrivateKey.generate()


def pqc_public(private):
    return private.public_key().public_bytes_raw().hex()


def pqc_lock(public_hex):
    aes_key, ciphertext = MLKEM768PublicKey.from_public_bytes(bytes.fromhex(public_hex)).encapsulate()
    return bytes(aes_key), bytes(ciphertext).hex()


def pqc_unlock(private, ciphertext_hex):
    return bytes(private.decapsulate(bytes.fromhex(ciphertext_hex)))


# Talking over TCP: one JSON object per line
def send(sock, obj):
    sock.sendall((json.dumps(obj) + '\n').encode())

