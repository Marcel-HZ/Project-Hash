"""Step 3: 盐值机制。"""

from __future__ import annotations

from hash_impl.sha256 import SHA256
import secrets

from context import get_password, set_sample
def _sha256(data):
    s=SHA256(); s.update(data); return s.digest()

from utils.formatting import print_step_header, print_success, print_info, print_warning

LECTURE_SALT = """\
盐值 (Salt) 是防御彩虹表与字典攻击的核心手段。

原理：
  1. 盐是一个随机、唯一的字节串，与密码拼接后再哈希：hash = H(salt || password)。
  2. 即使两个用户使用相同密码，因盐不同，其哈希值也完全不同。
  3. 攻击者无法使用预计算的彩虹表，必须对每个盐单独暴力破解。

存储格式（推荐）：$algo$iter$salt$hash
  - algo:  算法标识 (如 sha256, pbkdf2)
  - iter:  迭代次数（慢哈希参数）
  - salt:  十六进制或 Base64 编码的盐值
  - hash:  最终哈希/派生密钥

无盐模拟：直接对密码做 SHA-256，相同输入永远产生相同输出。
"""

SALT_SAMPLE_CODE = '''\
def hash_with_salt(pwd: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    return _sha256(salt + pwd.encode()), salt
'''


def hash_with_salt(pwd: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    return _sha256(salt + pwd.encode()), salt


def demo() -> None:
    print_step_header(3, "盐值机制")

    pwd = get_password()
    print_info(f"明文: {pwd!r}")

    no_salt_hash = _sha256(pwd.encode()).hex()
    print_warning(f"无盐 SHA-256: {no_salt_hash}")

    h1, s1 = hash_with_salt(pwd)
    h2, s2 = hash_with_salt(pwd)
    print_success(f"加盐1: {h1.hex()}")
    print_info(f"  盐值: {s1.hex()}")
    print_info(f"加盐2: {h2.hex()}")
    print_info(f"  盐值: {s2.hex()}")

    if h1 != h2:
        print_success("相同密码 + 不同盐 → 不同哈希，彩虹表失效。")

    sample = f"""\
明文: {pwd!r}
无盐 SHA-256: {no_salt_hash}
加盐1: {h1.hex()}
  盐值: {s1.hex()}
加盐2: {h2.hex()}
  盐值: {s2.hex()}
→ 相同密码 + 不同盐 → 不同哈希，彩虹表失效。
"""
    set_sample(3, sample)


def collect_section():
    from utils.markdown import StepSection
    from context import get_sample

    pwd = get_password()
    sample = get_sample(3, f"明文: {pwd!r}\n无盐 SHA-256: <待生成>\n加盐1: <待生成>\n  盐值: <待生成>\n加盐2: <待生成>\n  盐值: <待生成>")
    return StepSection(3, "盐值机制", LECTURE_SALT, SALT_SAMPLE_CODE, sample)