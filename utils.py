import random, hashlib
import os
def miller_rabin(n: int, k: int = 5) -> bool:
    """
    Miller–Rabin 素性测试：
    - 对 n ≤ 3 的小数直接判断；
    - 偶数直接判合数；
    - 使用 2,3,5,7,11 作为底，跳过 >= n 的底数。
    """
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False

    # 写成 n-1 = d * 2^s
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in (2, 3, 5, 7, 11):
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bit_length: int) -> int:
    """生成指定位长的大素数"""
    while True:
        candidate = random.getrandbits(bit_length) | 1  # 保证为奇数
        if miller_rabin(candidate):
            return candidate

def extended_gcd(a: int, b: int) -> tuple:
    """扩展欧几里得算法，返回 (g, x, y) 使 ax+by=g"""
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y

def mod_inverse(e: int, phi: int) -> int:
    """计算 e 关于 φ 的模逆 d，满足 e·d ≡ 1 (mod φ)"""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi

# --- OAEP 填充/解填充（简化版） ---------------------------------------
def mgf1(seed: bytes, length: int, hash_algo=hashlib.sha1) -> bytes:
    """Mask Generation Function 1，用于 OAEP"""
    hlen = hash_algo().digest_size
    T = b''
    for counter in range((length + hlen - 1) // hlen):
        C = counter.to_bytes(4, 'big')
        T += hash_algo(seed + C).digest()
    return T[:length]


def oaep_pad(message: bytes, k: int, hash_algo=hashlib.sha1) -> bytes:
    """
    OAEP 填充（默认 SHA-1），k 为模长（字节数）
    结构：0x00 || maskedSeed (hlen) || maskedDB (k-hlen-1)
    """
    hlen = hash_algo().digest_size
    max_msg_len = k - 2 * hlen - 2
    if len(message) > max_msg_len:
        raise ValueError(f"Message too long. Max length: {max_msg_len}, actual: {len(message)}")

    # 计算PS长度并构造DB
    ps_length = k - hlen - 2 - len(message)
    if ps_length < 0:
        raise ValueError("Invalid PS length. Check k and hash algorithm.")
    ps = b'\x00' * ps_length
    db = ps + b'\x01' + message

    # 确保DB长度正确
    if len(db) != k - hlen - 1:
        raise ValueError(f"DB length mismatch. Expected: {k - hlen -1}, actual: {len(db)}")

    # 生成随机种子并应用MGF掩码
    seed = os.urandom(hlen)
    db_mask = mgf1(seed, len(db), hash_algo)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hlen, hash_algo)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return b'\x00' + masked_seed + masked_db


def oaep_unpad(padded: bytes, hash_algo=hashlib.sha1) -> bytes:
    """OAEP 解填充（默认 SHA-1），返回原始明文"""
    hlen = hash_algo().digest_size
    if len(padded) < 1 + hlen:
        raise ValueError("Invalid padded data length")

    # 提取掩码部分并恢复种子和DB
    if padded[0] != 0:
        raise ValueError("Invalid leading byte")
    masked_seed = padded[1:1 + hlen]
    masked_db = padded[1 + hlen:]

    # 恢复种子和DB
    seed_mask = mgf1(masked_db, hlen, hash_algo)
    seed = bytes(s ^ sm for s, sm in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, len(masked_db), hash_algo)
    db = bytes(d ^ dm for d, dm in zip(masked_db, db_mask))

    # 查找分隔符0x01
    try:
        sep_idx = db.index(b'\x01')
    except ValueError:
        raise ValueError("Separator 0x01 not found in DB")

    # 返回分隔符后的原始消息
    return db[sep_idx + 1:]
def fast_mod_pow(base: int, exponent: int, mod: int) -> int:
    """
    快速模幂（二进制指数算法），计算 (base ** exponent) % mod，
    时间复杂度 O(log exponent)。
    """
    result = 1
    base %= mod
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exponent >>= 1
    return result
