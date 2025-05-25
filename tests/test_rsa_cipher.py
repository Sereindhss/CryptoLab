# tests/test_rsa_cipher.py
import unittest
from rsa_cipher import generate_rsa_keypair, encrypt_rsa, decrypt_rsa

class TestRSACipher(unittest.TestCase):
    def test_roundtrip(self):
        pub, priv = generate_rsa_keypair(512)
        msg = b"unit test"
        ct = encrypt_rsa(msg, pub)
        pt = decrypt_rsa(ct, priv)
        self.assertEqual(pt, msg)

    def test_empty_string(self):
        pub, priv = generate_rsa_keypair(512)
        msg = b""
        ct = encrypt_rsa(msg, pub)
        pt = decrypt_rsa(ct, priv)
        self.assertEqual(pt, msg)

    def test_special_chars(self):
        pub, priv = generate_rsa_keypair(512)
        msg = "特殊!@#".encode('utf-8')
        ct = encrypt_rsa(msg, pub)
        pt = decrypt_rsa(ct, priv)
        self.assertEqual(pt, msg)

    def test_too_long(self):
        pub, priv = generate_rsa_keypair(512)
        # 计算最大明文长度
        k = 64  # 512位/8
        from utils import oaep_pad
        max_msg_len = k - 2 * 20 - 2  # SHA-1
        msg = b"a" * (max_msg_len + 1)
        with self.assertRaises(ValueError):
            encrypt_rsa(msg, pub)


if __name__ == '__main__':
    unittest.main()
