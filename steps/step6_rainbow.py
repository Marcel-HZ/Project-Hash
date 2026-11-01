"""Step 6: 彩虹表攻击演示。"""

from __future__ import annotations

from hash_impl.sha256 import SHA256
from hash_impl.hmac import hmac_sha256
import secrets
import time

from context import get_password, set_sample
from utils.formatting import print_step_header, print_success, print_info, print_error, print_warning, prompt_continue

# ---------------- 进度条兼容 ----------------
try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        """没有安装 tqdm 时的降级实现"""
        desc = kwargs.get("desc", "")
        total = kwargs.get("total", None)
        if desc:
            if total is not None:
                print(f"  {desc} (共 {total} 项)...")
            else:
                print(f"  {desc}...")
        return iterable
# ------------------------------------------

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
    s = SHA256()
    s.update(data)
    return s.digest()


def _slow_hash(data: bytes) -> bytes:
    # PBKDF2 based on autonomous HMAC-SHA256（教学用，迭代次数较低）
    salt = b"fixed_salt"
    key = data
    u = hmac_sha256(key, salt + b"\x00\x00\x00\x01")
    result = u
    for _ in range(999):
        u = hmac_sha256(key, u)
        result = bytes(a ^ b for a, b in zip(result, u))
    return result[:32]


def build_rainbow_table(words: list[str], hash_fn, chain_len: int = 1000) -> dict:
    table: dict[str, str] = {}
    for start in tqdm(words, desc="构建彩虹表", unit="pwd", leave=False):
        h = hash_fn(start.encode())
        for _ in range(chain_len):
            h = hash_fn(h.encode())
        table[h] = start
    return table


def crack(hash_val: str, table: dict, hash_fn, chain_len: int = 1000) -> str | None:
    for i in tqdm(range(chain_len + 1), desc="尝试破解", unit="chain", leave=False):
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


def estimate_build_time(words: list[str], hash_fn, chain_len: int, sample_size: int = 3) -> float:
    """用少量样本估算完整构建时间（秒）"""
    sample = words[:sample_size]
    start = time.perf_counter()
    for pwd in sample:
        h = hash_fn(pwd.encode())
        for _ in range(chain_len):
            h = hash_fn(h.encode())
    elapsed = time.perf_counter() - start
    # 估算全部时间
    return elapsed / sample_size * len(words)


def demo() -> None:
    print_step_header(6, "彩虹表攻击演示")

    pwd = get_password()
    print_info(f"明文: {pwd!r}")

    base_words = ["password", "123456", "admin", "letmein", "qwerty", "welcome", "monkey", "dragon"]
    words = [f"{w}{i}" for w in base_words for i in range(125)]  # 共 1000 个
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
    MAX_BUILD_SECONDS = 30 * 60   # 30 分钟

    for label, hash_fn, use_salt in scenarios:
        print_info(f"--- 场景: {label} ---")
        table_salt = b""
        target_salt = secrets.token_bytes(8) if use_salt else b""

        def fn(data: bytes, s: bytes = table_salt) -> str:
            return hash_fn(s + data).hex()

        target_hash = hash_fn(target_salt + target.encode()).hex()
        chain_len = 20 if label.startswith("慢哈希") else 100

        print_info(f"字典大小: {len(words)}，链长度: {chain_len}")

        # ---------- 慢哈希特殊处理 ----------
        if label.startswith("慢哈希"):
            print_info("正在估算构建时间...")
            estimated = estimate_build_time(words, fn, chain_len, sample_size=2)
            print_info(f"预计构建时间: {estimated/60:.1f} 分钟")

            if estimated > MAX_BUILD_SECONDS:
                print_warning(f"预计构建时间超过 30 分钟，跳过实际构建。")
                print_info(f"理论破解成本极高（慢哈希 + 链长度 {chain_len}），在现实中几乎不可行。")
                results.append((
                    label,
                    target_hash,
                    target_salt.hex() if use_salt else "",
                    None,
                    "跳过（预计过久）",
                    estimated,   # 用估算时间
                    0.0
                ))
                print()
                continue
        # ------------------------------------

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

        print()

    # 生成样本记录
    lines = [f"明文: {pwd!r}", ""]
    for label, thash, tsalt, found, status, btime, ctime in results:
        lines.append(f"--- 场景: {label} ---")
        lines.append(f"目标哈希: {thash}")
        if tsalt:
            lines.append(f"盐值: {tsalt}")
        if status.startswith("跳过"):
            lines.append(f"预计构建时间: {btime/60:.1f} 分钟（已跳过实际构建）")
            lines.append(f"破解结果: {status}")
        else:
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