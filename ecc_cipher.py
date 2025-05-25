import random
from typing import NamedTuple
import random
import os
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Point(NamedTuple):
    x: int
    y: int

O = Point(None, None)

# 曲线参数：secp256k1
curve_params = {
    'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    'a': 0,
    'b': 7,
    'G': Point(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    ),
    'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
}
def inverse_mod(a: int, p: int) -> int:
    """有限域模逆"""
    return pow(a, -1, p)

def point_add(P: Point, Q: Point, a: int, p: int) -> Point:
    """椭圆曲线点加法"""
    if P == O: return Q
    if Q == O: return P
    if P.x == Q.x and (P.y + Q.y) % p == 0:
        return O
    if P != Q:
        lam = ((Q.y - P.y) * inverse_mod(Q.x - P.x, p)) % p
    else:
        lam = ((3 * P.x*P.x + a) * inverse_mod(2 * P.y, p)) % p
    x3 = (lam*lam - P.x - Q.x) % p
    y3 = (lam*(P.x - x3) - P.y) % p
    return Point(x3, y3)

def scalar_mul(P: Point, k: int, a: int, p: int) -> Point:
    """双倍-加算法实现标量乘法"""
    R, Q = O, P
    while k:
        if k & 1:
            R = point_add(R, Q, a, p)
        Q = point_add(Q, Q, a, p)
        k >>= 1
    return R

def generate_ecc_keypair(curve_params: dict) -> tuple:
    """
    curve_params 包含 {p, a, b, G: Point, n}
    返回 (private_d, public_Q)
    """
    d = random.randrange(1, curve_params['n'])
    Q = scalar_mul(curve_params['G'], d, curve_params['a'], curve_params['p'])
    return d, Q

def encrypt_ecc(M: Point, Q: Point, curve_params: dict) -> tuple:
    k = random.randrange(1, curve_params['n'])
    C1 = scalar_mul(curve_params['G'], k, curve_params['a'], curve_params['p'])
    kQ = scalar_mul(Q, k, curve_params['a'], curve_params['p'])
    C2 = point_add(M, kQ, curve_params['a'], curve_params['p'])
    return C1, C2

def decrypt_ecc(C1: Point, C2: Point, d: int, curve_params: dict) -> Point:
    dC1 = scalar_mul(C1, d, curve_params['a'], curve_params['p'])
    # 求逆点
    inv = Point(dC1.x, (-dC1.y) % curve_params['p'])
    M = point_add(C2, inv, curve_params['a'], curve_params['p'])
    return M

def encode_point_from_text(text, curve_params):
    m_int = int.from_bytes(text.encode('utf-8'), 'big')
    p, a, b = curve_params['p'], curve_params['a'], curve_params['b']
    x = m_int
    while x < p:
        rhs = (x**3 + a*x + b) % p
        # 仅适用于p%4==3的曲线
        y = pow(rhs, (p+1)//4, p)
        if pow(y, 2, p) == rhs:
            return Point(x, y)
        x += 1
    raise ValueError('无法嵌入明文到曲线点')

def decode_point_to_text(P):
    m_int = P.x
    if m_int == 0:
        return ""
    try:
        return m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big').decode('utf-8')
    except Exception:
        return str(m_int)

def ecies_encrypt(plaintext: bytes, recipient_pub: Point, curve_params: dict) -> tuple:
    # 1. 生成临时密钥对
    k = int.from_bytes(os.urandom(32), 'big') % curve_params['n']
    R = scalar_mul(curve_params['G'], k, curve_params['a'], curve_params['p'])  # 临时公钥
    # 2. 计算共享密钥
    S = scalar_mul(recipient_pub, k, curve_params['a'], curve_params['p'])
    shared_secret = hashlib.sha256(str(S.x).encode() + str(S.y).encode()).digest()
    # 3. 对称加密
    cipher = AES.new(shared_secret[:16], AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = cipher.iv
    # 4. 生成MAC
    mac = hmac.new(shared_secret, iv + ct_bytes, hashlib.sha256).digest()
    # 5. 返回密文（临时公钥R, iv, 密文, mac）
    return (R.x, R.y), iv, ct_bytes, mac

def ecies_decrypt(cipher_tuple: tuple, recipient_priv: int, curve_params: dict) -> bytes:
    (Rx, Ry), iv, ct_bytes, mac = cipher_tuple
    R = Point(Rx, Ry)
    # 1. 计算共享密钥
    S = scalar_mul(R, recipient_priv, curve_params['a'], curve_params['p'])
    shared_secret = hashlib.sha256(str(S.x).encode() + str(S.y).encode()).digest()
    # 2. 验证MAC
    mac_check = hmac.new(shared_secret, iv + ct_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, mac_check):
        raise ValueError("MAC check failed")
    # 3. 对称解密
    cipher = AES.new(shared_secret[:16], AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return plaintext
