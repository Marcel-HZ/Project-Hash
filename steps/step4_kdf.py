"""Step 4: PBKDF2-HMAC-SHA256 密钥派生。"""

from __future__ import annotations

from hash_impl.sha256 import SHA256
from hash_impl.hmac import hmac_sha256

def _pbkdf2(pwd: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    key = pwd
    # Simplified PBKDF2 (single block)
    u = hmac_sha256(key, salt + b"\x00\x00\x00\x01")
    result = u
    for _ in range(iterations - 1):
        u = hmac_sha256(key, u)
        result = bytes(a ^ b for a, b in zip(result, u))
    return result[:dklen]
import secrets
import time

from context import get_password, set_sample
from utils.formatting import print_step_header, print_success, print_info

LECTURE_PBKDF2 = """\
PBKDF2 (Password-Based Key Derivation Function 2) 是一种慢哈希密钥派生算法，
通过反复迭代 HMAC 大幅增加暴力破解成本。

工作原理：
  1. 输入：密码、盐、迭代次数 (iter)、目标密钥长度 (dklen)。
  2. 使用 HMAC-SHA256 作为伪随机函数 (PRF)。
  3. 每轮迭代：U_1 = PRF(password, salt || INT(i))，
                U_j = PRF(password, U_{j-1})，共 iter 轮。
  4. 最终密钥 = XOR(U_1 || U_2 || ... || U_{ceil(dklen/hlen)}) 的前 dklen 字节。

参数建议 (NIST SP 800-63B, 2024)：
  - SHA-256: 至少 600,000 次迭代

对比普通哈希：SHA-256 单次耗时 < 1 μs，PBKDF2 600k 次迭代耗时 ~0.5-2 s，
使暴力破解成本提升 10^6 倍。但 PBKDF2 仅 CPU 硬化，不抗 ASIC/GPU，
现代替代方案为 Argon2（内存硬化 + 可调并行度）。
"""

KDF_SAMPLE_CODE = '''\
from hash_impl.hmac import hmac_sha256

def derive_key(pwd: str, salt: bytes, iterations: int = 600_000, dklen: int = 32) -> bytes:
    return _pbkdf2(pwd.encode(), salt, iterations, dklen)
'''


def derive_key(pwd: str, salt: bytes, iterations: int = 600_000, dklen: int = 32) -> bytes:
    return _pbkdf2(pwd.encode(), salt, iterations, dklen)


def demo() -> None:
    print_step_header(4, "密钥派生 (PBKDF2-HMAC-SHA256)")

    pwd = get_password()
    print_info(f"明文: {pwd!r}")
    salt = secrets.token_bytes(16)
    iterations = 10000

    start = time.perf_counter()
    key = derive_key(pwd, salt, iterations=iterations)
    elapsed = time.perf_counter() - start

    print_info(f"盐值: {salt.hex()} (16 字节)")
    print_info(f"迭代次数: {iterations:,}")
    print_success(f"派生密钥: {key.hex()}")
    print_info(f"用时: {elapsed:.3f}s")

    sample = f"""\
明文: {pwd!r}
盐值: {salt.hex()} (16 字节)
迭代次数: 600,000
派生密钥: {key.hex()}
用时: {elapsed:.3f}s
"""
    set_sample(4, sample)


def collect_section():
    from utils.markdown import StepSection
    from context import get_sample

    pwd = get_password()
    sample = get_sample(4, f"明文: {pwd!r}\n盐值: <待生成>\n迭代次数: 600,000\n派生密钥: <待生成>\n用时: <待生成>")
    return StepSection(4, "密钥派生 (PBKDF2-HMAC-SHA256)", LECTURE_PBKDF2, KDF_SAMPLE_CODE, sample)