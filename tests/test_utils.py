# tests/test_utils.py
import unittest
from utils import miller_rabin, generate_prime, extended_gcd, mod_inverse, oaep_pad, oaep_unpad

class TestUtils(unittest.TestCase):
    def test_miller_rabin(self):
        for prime in [2,3,5,7,11, 7919]:
            self.assertTrue(miller_rabin(prime))
        self.assertFalse(miller_rabin(1))
        self.assertFalse(miller_rabin(4))
    def test_mod_inverse(self):
        self.assertEqual((3 * mod_inverse(3, 11)) % 11, 1)
    def test_oaep(self):
        msg = b"hello"
        k = 64  # 512-bit 模长（单位字节）
        padded = oaep_pad(msg, k)
        self.assertEqual(oaep_unpad(padded), msg)


if __name__ == '__main__':
    unittest.main()