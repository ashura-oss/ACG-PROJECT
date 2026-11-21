import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common
import shor


class Tests(unittest.TestCase):
    def test_rsa_lock(self):
        for _ in range(20):
            n, e, d = common.rsa_keys()
            key = os.urandom(32)
            self.assertEqual(common.rsa_unlock(common.rsa_lock(key, n, e), n, d), key)

    def test_pqc_lock(self):
        private = common.pqc_keys()
        key, ciphertext = common.pqc_lock(common.pqc_public(private))
        self.assertEqual(common.pqc_unlock(private, ciphertext), key)

    def test_aes(self):
        key = os.urandom(32)
        self.assertEqual(common.decrypt(key, common.encrypt(key, 'hi')), 'hi')

    def test_shor_cracks_the_rsa_lock(self):
        n, e, d = common.rsa_keys()
        key = os.urandom(32)
        p, q = shor.crack(n)['factors']
        self.assertEqual(p * q, n)
        cracked_d = pow(e, -1, (p - 1) * (q - 1))
        self.assertEqual(common.rsa_unlock(common.rsa_lock(key, n, e), n, cracked_d), key)


if __name__ == '__main__':
    unittest.main()
