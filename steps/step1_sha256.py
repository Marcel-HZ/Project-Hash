"""Step 1: SHA-256 基础哈希。"""

from __future__ import annotations

import base64

from context import get_password, set_sample
from hash_impl.sha256 import SHA256
from utils.formatting import print_step_header, print_success, print_info

LECTURE_SHA256 = """\
SHA-256 属于 SHA-2 家族，由 NSA 设计、NIST 标准化 (FIPS 180-4)。

核心结构：Merkle-Damgard
  1. 填充：消息末尾追加 1 位，再补 0 直至长度 ≡ 448 (mod 512)，最后写入 64 位原始长度。
  2. 分块：填充后的消息被切分为 512-bit（64 字节）的消息块。
  3. 初始化：8 个 32-bit 初始常量 (IV)，取自前 8 个素数的平方根小数部分。
  4. 压缩函数：每个块经 64 轮迭代，使用逻辑函数 (Ch, Maj, Σ0, Σ1) 与模 2^32 加法。
  5. 输出：所有块处理完毕后，拼接 8 个 32-bit 工作变量 → 256-bit (32 字节) 摘要。

特性：单向、抗碰撞性强、雪崩效应（输入 1 bit 变化 → 输出约 50% bit 翻转）。
"""

SHA256_SAMPLE_CODE = '''\
from hash_impl.sha256 import SHA256

def sha256_digest(data: bytes) -> bytes:
    s = SHA256()
    s.update(data)
    return s.digest()

hex_digest = sha256_digest(password.encode()).hex()
b64_digest = base64.b64encode(sha256_digest(password.encode())).decode()
'''

def sha256_digest(data: bytes) -> bytes:
    s = SHA256()
    s.update(data)
    return s.digest()


def demo() -> None:
    print_step_header(1, "SHA-256 基础哈希")

    pwd = get_password()
    print_info(f"明文: {pwd!r}")

    raw = pwd.encode("utf-8")
    digest = sha256_digest(raw)
    hex_out = digest.hex()
    b64_out = base64.b64encode(digest).decode("ascii")
    print_success(f"Hex:   {hex_out}")
    print_info(f"Base64: {b64_out}")

    if pwd:
        first_char = chr(ord(pwd[0]) ^ 1)
        slightly_changed = first_char + pwd[1:]
        changed_digest = sha256_digest(slightly_changed.encode()).hex()
        print_info(f"微调 1 bit: {slightly_changed!r}")
        print_info(f"  Hex: {changed_digest}")

    sample = f"""\
明文: {pwd!r}
SHA-256 Hex:   {hex_out}
SHA-256 Base64: {b64_out}
"""
    set_sample(1, sample)


def collect_section():
    from utils.markdown import StepSection
    from context import get_sample

    pwd = get_password()
    sample = get_sample(1, f"明文: {pwd!r}\nSHA-256 Hex:   <待生成>\nSHA-256 Base64: <待生成>")
    return StepSection(1, "SHA-256 基础哈希", LECTURE_SHA256, SHA256_SAMPLE_CODE, sample)