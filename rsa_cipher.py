from utils import generate_prime, mod_inverse, oaep_pad, oaep_unpad
import math
from typing import NamedTuple
import random

class Point(NamedTuple):
    x: int
    y: int

O = Point(None, None)

# 定义曲线 secp256k1 参数
curve_params = {
    'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    'a': 0,
    'b': 7,
    'G': Point(
        55066263022277343669578718895168534326250603453777594175500187360389116729240,
        32670510020758816978083085130507043184471273337482424
    ),
    'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
}
def generate_rsa_keypair(bit_length: int = 2048) -> tuple:
    """生成 RSA 公私钥对"""
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # 常用公钥指数:contentReference[oaicite:4]{index=4}:contentReference[oaicite:5]{index=5}
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt_rsa(plaintext: bytes, public_key: tuple) -> int:
    """RSA 加密：先 OAEP 填充，再模幂运算"""
    e, n = public_key
    k = math.ceil(n.bit_length() / 8)
    padded = oaep_pad(plaintext, k)
    m = int.from_bytes(padded, 'big')
    return pow(m, e, n)

def decrypt_rsa(cipher_int: int, private_key: tuple) -> bytes:
    """RSA 解密：先模幂，再 OAEP 解填充"""
    d, n = private_key
    k = math.ceil(n.bit_length() / 8)
    m = pow(cipher_int, d, n)
    padded = m.to_bytes(k, 'big')
    return oaep_unpad(padded)

def fast_mod_pow(base: int, exponent: int, mod: int) -> int:
    """
    快速模幂（binary exponentiation）
    计算 (base ** exponent) % mod，时间复杂度 O(log exponent)。
    """
    result = 1
    base %= mod
    while exponent > 0:
        # 如果当前最低位为 1，则累乘
        if exponent & 1:
            result = (result * base) % mod
        # 平方基数
        base = (base * base) % mod
        # 右移位，相当于 exponent //= 2
        exponent >>= 1
    return result