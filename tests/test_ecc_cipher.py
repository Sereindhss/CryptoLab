# tests/test_ecc_cipher.py
import unittest
from ecc_cipher import generate_ecc_keypair, encrypt_ecc, decrypt_ecc, Point,curve_params

class TestECCCipher(unittest.TestCase):
    def test_roundtrip(self):
        priv, pub = generate_ecc_keypair(curve_params)
        # 以 G 点为"明文"
        M = curve_params['G']
        C1, C2 = encrypt_ecc(M, pub, curve_params)
        P = decrypt_ecc(C1, C2, priv, curve_params)
        self.assertEqual(P, M)

    def test_too_long(self):
        priv, pub = generate_ecc_keypair(curve_params)
        from ecc_cipher import encode_point_from_text
        # 构造超长明文
        p = curve_params['p']
        max_bytes = (p.bit_length() // 8)
        msg = "a" * (max_bytes + 10)
        with self.assertRaises(ValueError):
            encode_point_from_text(msg, curve_params)

    def test_ecies_roundtrip(self):
        priv, pub = generate_ecc_keypair(curve_params)
        from ecc_cipher import ecies_encrypt, ecies_decrypt
        msg = "hello,ECIES!特殊字符123"
        ct = ecies_encrypt(msg.encode('utf-8'), pub, curve_params)
        pt = ecies_decrypt(ct, priv, curve_params).decode('utf-8')
        self.assertEqual(pt, msg)

if __name__ == '__main__':
    unittest.main()
