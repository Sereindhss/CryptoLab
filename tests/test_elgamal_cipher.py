# tests/test_elgamal_cipher.py
import unittest
from elgamal_cipher import generate_elgamal_keypair, encrypt_elgamal, decrypt_elgamal

class TestElGamalCipher(unittest.TestCase):
    def test_roundtrip(self):
        pub, priv = generate_elgamal_keypair(256)
        msg = 123456
        ct = encrypt_elgamal(msg, pub, hmac_key=b'testkey')
        pt = decrypt_elgamal(ct, priv, hmac_key=b'testkey', public_key=pub)
        self.assertEqual(pt, msg)

    def test_empty_string(self):
        pub, priv = generate_elgamal_keypair(256)
        msg = b""
        m = int.from_bytes(msg, 'big')
        ct = encrypt_elgamal(m, pub, hmac_key=b'testkey')
        pt = decrypt_elgamal(ct, priv, hmac_key=b'testkey', public_key=pub)
        self.assertEqual(pt, m)

    def test_special_chars(self):
        pub, priv = generate_elgamal_keypair(512)
        msg = "特殊!@#".encode('utf-8')
        m = int.from_bytes(msg, 'big')
        ct = encrypt_elgamal(m, pub, hmac_key=b'testkey')
        pt = decrypt_elgamal(ct, priv, hmac_key=b'testkey', public_key=pub)
        self.assertEqual(pt, m)

    def test_too_long(self):
        pub, priv = generate_elgamal_keypair(256)
        p = pub[0]
        msg = b"a" * ((p.bit_length() // 8) + 1)
        m = int.from_bytes(msg, 'big')
        with self.assertRaises(ValueError):
            encrypt_elgamal(m, pub, hmac_key=b'testkey')

if __name__ == '__main__':
    unittest.main()
