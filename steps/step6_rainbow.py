"""Step 6: 彩虹表攻击演示。"""

from __future__ import annotations

import hashlib
import secrets
import time

from context import get_password, set_sample
from utils.formatting import print_step_header, print_success, print_info, print_error, prompt_continue

LECTURE_RAINBOW = """\
彩虹表 (Rainbow Table) 是一种时间-空间权衡攻击技术，用于逆向哈希函数。

核心思想：
  1. 预计算：对大量候选密码反复哈希，生成链，只保存每条链的起点与终点。
  2. 查表：对目标哈希值，沿相同链函数反向查找，若命中则恢复原始候选密码。

为什么盐值能防御彩虹表：
  - 盐值未知时，攻击者无法预计算通用彩虹表，必须为每个盐单独建表。

为什么慢哈希能增加成本：
  - PBKDF2/Argon2 使单次哈希耗时增加，彩虹表每条链需调用链函数 chain_len 次，
    总成本 = chain_len × 单次耗时，使暴力破解在可行时间内变得不现实。

本演示使用 1000 词小字典，对比 4 组场景：
  1. 快哈希 + 无盐
  2. 快哈希 + 有盐
  3. 慢哈希 + 无盐
  4. 慢哈希 + 有盐
"""

RAINBOW_SAMPLE_CODE = '''\
def build_rainbow_table(words, hash_fn, chain_len=1000):
    table = {}
    for start in words:
        h = hash_fn(start.encode())
        for _ in range(chain_len):
            h = hash_fn(h.encode())
        table[h] = start
    return table


def crack(hash_val, table, hash_fn, chain_len=1000):
    for i in range(chain_len + 1):
        h = hash_val
        for _ in range(chain_len - i):
            h = hash_fn(h.encode())
        if h in table:
            start = table[h]
            cur = hash_fn(start.encode())
            if cur == hash_val:
                return start
            for _ in range(i):
                cur = hash_fn(cur.encode())
                if cur == hash_val:
                    return start
    return None
'''


def _fast_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _slow_hash(data: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", data, b"fixed_salt", 1000, dklen=32)


def build_rainbow_table(words: list[str], hash_fn, chain_len: int = 1000) -> dict:
    table: dict[str, str] = {}
    for start in words:
        h = hash_fn(start.encode())
        for _ in range(chain_len):
            h = hash_fn(h.encode())
        table[h] = start
    return table


def crack(hash_val: str, table: dict, hash_fn, chain_len: int = 1000) -> str | None:
    for i in range(chain_len + 1):
        h = hash_val
        for _ in range(chain_len - i):
            h = hash_fn(h.encode())
        if h in table:
            start = table[h]
            cur = hash_fn(start.encode())
            if cur == hash_val:
                return start
            for _ in range(i):
                cur = hash_fn(cur.encode())
                if cur == hash_val:
                    return start
    return None


def demo() -> None:
    print_step_header(6, "彩虹表攻击演示")

    pwd = get_password()
    print_info(f"明文: {pwd!r}")

    base_words = ["password", "123456", "admin", "letmein", "qwerty", "welcome", "monkey", "dragon"]
    words = [f"{w}{i}" for w in base_words for i in range(125)]
    if pwd not in words:
        words.append(pwd)
    target = pwd

    scenarios = [
        ("快哈希 + 无盐", _fast_hash, False),
        ("快哈希 + 有盐", _fast_hash, True),
        ("慢哈希 + 无盐", _slow_hash, False),
        ("慢哈希 + 有盐", _slow_hash, True),
    ]

    results = []

    for label, hash_fn, use_salt in scenarios:
        print_info(f"--- 场景: {label} ---")
        table_salt = b""
        target_salt = secrets.token_bytes(8) if use_salt else b""

        def fn(data: bytes, s: bytes = table_salt) -> str:
            return hash_fn(s + data).hex()

        target_hash = hash_fn(target_salt + target.encode()).hex()
        chain_len = 50 if label.startswith("慢哈希") else 200

        start = time.perf_counter()
        table = build_rainbow_table(words, fn, chain_len=chain_len)
        build_time = time.perf_counter() - start

        start2 = time.perf_counter()
        result = crack(target_hash, table, fn, chain_len=chain_len)
        crack_time = time.perf_counter() - start2

        print_info(f"彩虹表构建用时: {build_time:.3f}s")
        print_info(f"破解用时: {crack_time:.3f}s")

        if result == target:
            print_success(f"破解成功！找到密码: {result}")
            results.append((label, target_hash, target_salt.hex(), result, "成功", build_time, crack_time))
        else:
            print_error(f"破解失败（未在彩虹表中找到匹配）")
            results.append((label, target_hash, target_salt.hex(), None, "失败", build_time, crack_time))

    lines = [f"明文: {pwd!r}", ""]
    for label, thash, tsalt, found, status, btime, ctime in results:
        lines.append(f"--- 场景: {label} ---")
        lines.append(f"目标哈希: {thash}")
        if tsalt:
            lines.append(f"盐值: {tsalt}")
        lines.append(f"彩虹表构建用时: {btime:.3f}s")
        lines.append(f"破解用时: {ctime:.3f}s")
        lines.append(f"破解结果: {status}" + (f" → 找到密码: {found}" if found else " → 未找到匹配"))
        lines.append("")
    set_sample(6, "\n".join(lines))

    prompt_continue("所有步骤已完成，按回车结束...")


def collect_section():
    from utils.markdown import StepSection
    from context import get_sample

    pwd = get_password()
    sample = get_sample(6, f"明文: {pwd!r}\n<等待运行生成真实样本>")
    return StepSection(6, "彩虹表攻击演示", LECTURE_RAINBOW, RAINBOW_SAMPLE_CODE, sample)