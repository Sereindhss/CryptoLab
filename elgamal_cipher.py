import random, hashlib, hmac
from utils import miller_rabin, generate_prime, mod_inverse, fast_mod_pow


def generate_elgamal_keypair(bit_length: int = 1024) -> tuple:
    """生成 ElGamal 公私钥对，支持可变密钥长度"""
    p = generate_prime(bit_length)
    # 找 g，使其为生成元（简化：随机试验）
    g = random.randrange(2, p - 1)
    x = random.randrange(1, p - 1)  # 私钥
    y = fast_mod_pow(g, x, p)  # 公钥
    return (p, g, y), x


def encrypt_elgamal(plaintext: int, public_key: tuple, hmac_key: bytes) -> tuple:
    """ElGamal 加密，附加 HMAC 验证"""
    p, g, y = public_key
    if plaintext >= p:
        raise ValueError("明文数值必须小于素数 p")

    k = random.randrange(1, p - 1)
    c1 = fast_mod_pow(g, k, p)
    c2 = (plaintext * fast_mod_pow(y, k, p)) % p
    # 计算 HMAC-SHA256(c1||c2)
    msg = c1.to_bytes((p.bit_length() + 7) // 8, 'big') + \
          c2.to_bytes((p.bit_length() + 7) // 8, 'big')
    tag = hmac.new(hmac_key, msg, hashlib.sha256).digest()
    return (c1, c2, tag)


def decrypt_elgamal(cipher: tuple, private_key: int, hmac_key: bytes, public_key: tuple) -> int:
    """ElGamal 解密，验证 HMAC"""
    p, _, _ = public_key
    c1, c2, tag = cipher
    # 验证 HMAC
    msg = c1.to_bytes((p.bit_length() + 7) // 8, 'big') + \
          c2.to_bytes((p.bit_length() + 7) // 8, 'big')
    if not hmac.compare_digest(tag, hmac.new(hmac_key, msg, hashlib.sha256).digest()):
        raise ValueError("HMAC verification failed")
    s = fast_mod_pow(c1, private_key, p)
    s_inv = mod_inverse(s, p)
    return (c2 * s_inv) % p