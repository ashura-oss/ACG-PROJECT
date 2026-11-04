import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from attacker import recover_key
from decrypt import AuthenticationFailure, decrypt_message, parse_key
from main import decrypt_option, encrypt_option, main
from package_io import PackageError, load_package, save_package, validate_package
from sender import encrypt_message
from toy_rsa import decode_key, encode_key, unwrap_key, wrap_key

ROOT = Path(__file__).resolve().parents[1]


class EncodingTests(unittest.TestCase):
    def test_all_bytes(self):
        for value in range(256):
            key = bytes([value])*32
            self.assertEqual(decode_key(encode_key(key)), key)
            self.assertEqual(unwrap_key(wrap_key(key), 7), key)
            self.assertEqual(len(wrap_key(key)), 64)

    def test_all_digits(self):
        for digit in range(33):
            self.assertEqual(pow(pow(digit, 3, 33), 7, 33), digit)

    def test_invalid_decoding(self):
        for digits in ([1]*63, [33]*64, [True]*64, [32]*64):
            with self.assertRaises(ValueError): decode_key(digits)


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'package.json'
        self.key = bytes(range(32))
        with patch('sender.AESGCM.generate_key', return_value=self.key):
            self.package = encrypt_message('Hello 🔐')
        save_package(self.package, self.path)

    def test_utf8_empty_and_limit(self):
        for message in ('', 'HELLO', 'Agent007!', 'Hello 🔐', 'a'*4096, '🔐'*1024):
            package = encrypt_message(message)
            key, _ = recover_key(package, [3, 11])
            self.assertEqual(decrypt_message(package, key.hex()), message)
        for message in ('a'*4097, '🔐'*1025, 'two\nlines'):
            with self.assertRaises(ValueError): encrypt_message(message)

    def test_key_input(self):
        self.assertEqual(parse_key(' \t'+self.key.hex().upper()+'\n'), self.key)
        for text in ('', '0'*63, '0'*65, 'z'*64, '00 '*32, '0'*32+' '+'0'*32):
            with self.assertRaises(ValueError): parse_key(text)
        with self.assertRaises(AuthenticationFailure):
            decrypt_message(self.package, 'ff'*32)

    def test_public_package_and_randomness(self):
        self.assertEqual(load_package(self.path), self.package)
        self.assertNotIn(self.key.hex(), self.path.read_text())
        self.assertEqual(set(self.package), {'header', 'nonce_hex', 'ciphertext_and_tag_hex'})
        one, two = encrypt_message('same'), encrypt_message('same')
        self.assertNotEqual(one['nonce_hex'], two['nonce_hex'])
        self.assertNotEqual(one['header']['wrapped_key_digits'], two['header']['wrapped_key_digits'])

    def test_tampering(self):
        for field in ('nonce_hex', 'ciphertext_and_tag_hex'):
            for position in (0, -1):
                package = copy.deepcopy(self.package)
                value = list(package[field])
                value[position] = '1' if value[position] != '1' else '2'
                package[field] = ''.join(value)
                with self.assertRaises(AuthenticationFailure):
                    decrypt_message(package, self.key.hex())
        package = copy.deepcopy(self.package)
        package['header']['wrapped_key_digits'][0] ^= 1
        with self.assertRaises(AuthenticationFailure): decrypt_message(package, self.key.hex())

    def test_schema_rejection(self):
        mutations = [lambda p: p.update(extra=1), lambda p: p.pop('header'),
                     lambda p: p['header'].update(version=True),
                     lambda p: p['header'].update(version=2),
                     lambda p: p['header'].update(N=15),
                     lambda p: p['header'].update(e=3.0),
                     lambda p: p['header'].update(aes_algorithm='AES-CBC'),
                     lambda p: p['header'].update(extra=1),
                     lambda p: p['header'].update(wrapped_key_digits=[0]*63),
                     lambda p: p['header']['wrapped_key_digits'].__setitem__(0, True),
                     lambda p: p['header']['wrapped_key_digits'].__setitem__(0, 33),
                     lambda p: p.update(nonce_hex='00'*11),
                     lambda p: p.update(nonce_hex='gg'*12),
                     lambda p: p.update(ciphertext_and_tag_hex='00'*15),
                     lambda p: p.update(ciphertext_and_tag_hex='00'*4113)]
        for mutation in mutations:
            package = copy.deepcopy(self.package)
            mutation(package)
            with self.assertRaises(PackageError): validate_package(package)
        self.path.write_text('{"header": {}, "header": {}}')
        with self.assertRaisesRegex(PackageError, 'Duplicate'): load_package(self.path)
        self.path.write_text('{')
        with self.assertRaises(PackageError): load_package(self.path)
        with self.assertRaises(PackageError): load_package(self.path.with_name('missing'))

    def test_overwrite_cancellation(self):
        before = self.path.read_bytes()
        with patch('builtins.input', return_value='n'), redirect_stdout(io.StringIO()):
            encrypt_option(self.path)
        self.assertEqual(before, self.path.read_bytes())
        with self.assertRaises(FileExistsError): save_package(self.package, self.path)

    def test_manual_prompt_without_attack(self):
        output = io.StringIO()
        with patch('builtins.input', return_value=self.key.hex()) as prompt, redirect_stdout(output):
            decrypt_option(self.path)
        self.assertEqual(prompt.call_count, 1)
        self.assertIn('Hello 🔐', output.getvalue())

    def test_fresh_process_recovery(self):
        # Sender key is absent from the child process's arguments and environment.
        result = subprocess.run([sys.executable, str(ROOT/'attacker.py'), str(self.path), '--seed', '42'],
                                cwd=self.directory.name, capture_output=True, text=True,
                                encoding='utf-8', timeout=35, check=True)
        recovered = json.loads(result.stdout)
        self.assertEqual(bytes.fromhex(recovered['candidate_key_hex']), self.key)
        self.assertNotIn('Hello', result.stdout)
        self.assertEqual(decrypt_message(load_package(self.path), recovered['candidate_key_hex']), 'Hello 🔐')

    def test_cli_rehearsal_and_no_automatic_decryption(self):
        path = self.path.with_name('rehearsal.json')
        output = io.StringIO()
        recovered = []
        def interact(prompt):
            if prompt.startswith('Enter plaintext'): return 'REHEARSAL 🔐'
            if prompt.startswith('Press Enter'): return ''
            if prompt.startswith('Enter recovered'):
                recovered.append(True)
                # Simulate the user copying exactly the displayed line.
                text = output.getvalue().split('CANDIDATE RECOVERED AES-256 KEY (HEX):\n')[-1]
                return text.splitlines()[0]
            if prompt.startswith('Select option'):
                return next(choices)
            raise AssertionError(prompt)
        choices = iter(['1', '2', '3', '4'])
        with patch('builtins.input', side_effect=interact), redirect_stdout(output):
            main(path)
        transcript = output.getvalue()
        prefix, suffix = transcript.split('AES-GCM authentication successful.')
        self.assertNotIn('REHEARSAL', prefix)
        self.assertIn('REHEARSAL 🔐', suffix)
        self.assertEqual(recovered, [True])
        self.assertIn('Most frequent counting-register measurements:', transcript)


if __name__ == '__main__':
    unittest.main()
