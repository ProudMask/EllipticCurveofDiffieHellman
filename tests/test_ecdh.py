import json
import os
import subprocess
import sys
import unittest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from ecdh_demo import derive_key, encrypt, decrypt, run_demo


class ECDHTests(unittest.TestCase):
    def setUp(self):
        self.alice = ec.generate_private_key(ec.SECP256R1())
        self.bob = ec.generate_private_key(ec.SECP256R1())
        self.salt = os.urandom(32)
        self.key = derive_key(self.alice, self.bob.public_key(), self.salt)

    def test_independent_derivation(self):
        other = derive_key(self.bob, self.alice.public_key(), self.salt)
        self.assertEqual(self.key, other)
        self.assertEqual(len(self.key), 32)

    def test_unicode_and_empty_round_trip(self):
        for text in ('', 'مرحبا Haneen 🌷\0'):
            self.assertEqual(decrypt(encrypt(text, self.key), self.key), text)

    def test_tampering_rejected(self):
        nonce, ciphertext = encrypt('Synthetic test', self.key)
        changed = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        with self.assertRaises(InvalidTag):
            decrypt((nonce, changed), self.key)

    def test_wrong_key_and_salt(self):
        packet = encrypt('Synthetic test', self.key)
        wrong_key = derive_key(self.bob, self.alice.public_key(), os.urandom(32))
        with self.assertRaises(InvalidTag):
            decrypt(packet, wrong_key)

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            derive_key(self.alice, self.bob.public_key(), b'short')
        with self.assertRaises(ValueError):
            derive_key(self.alice, ec.generate_private_key(ec.SECP384R1()).public_key(), self.salt)
        with self.assertRaises(ValueError):
            decrypt((b'short', b'123'), self.key)
        with self.assertRaises(ValueError):
            encrypt('example', b'short')

    def test_cli_and_import(self):
        result = subprocess.run([sys.executable, 'ecdh_demo.py'], capture_output=True, text=True, check=True, timeout=10)
        report = json.loads(result.stdout)
        self.assertTrue(report['round_trip_verified'])
        self.assertTrue(report['derived_keys_match'])
        imported = subprocess.run([sys.executable, '-c', 'import ecdh_demo'], capture_output=True, text=True, timeout=10)
        self.assertEqual(imported.returncode, 0)
        self.assertEqual(imported.stdout, '')


if __name__ == '__main__':
    unittest.main()
