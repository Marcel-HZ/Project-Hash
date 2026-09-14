"""Step 2: Base64 编码。"""

from __future__ import annotations

import base64

from context import get_password, set_sample
from utils.formatting import print_step_header, print_success, print_info

LECTURE_BASE64 = """\
Base64 是一种将二进制数据编码为 ASCII 文本的方案，广泛用于邮件、URL、JWT 等场景。

编码原理：
  1. 输入按 3 字节（24 bit）分组。
  2. 每组切分为 4 个 6-bit 值（0-63）。
  3. 每个 6-bit 值映射到 Base64 字符表：
       A-Z (0-25)  a-z (26-51)  0-9 (52-61)  + (62)  / (63)
  4. 若最后组不足 3 字节，用 '=' 填充至 4 字符长度。

变体：
  - 标准 Base64：使用 '+' '/'，适合文件与二进制传输。
  - URL-safe Base64：将 '+' '/' 替换为 '-' '_'，去除 '=' 填充。

注意：Base64 是编码而非加密，不具备保密性，仅用于数据表示转换。
"""

B64_SAMPLE_CODE = '''\
def b64_encode(data: bytes, urlsafe: bool = False) -> str:
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return base64.b64encode(data).decode("ascii")

std = b64_encode(password.encode())
safe = b64_encode(password.encode(), urlsafe=True)
'''


def b64_encode(data: bytes, urlsafe: bool = False) -> str:
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return base64.b64encode(data).decode("ascii")


def demo() -> None:
    print_step_header(2, "Base64 编码")

    pwd = get_password()
    raw = pwd.encode("utf-8")
    std = b64_encode(raw)
    safe = b64_encode(raw, urlsafe=True)
    print_info(f"明文: {pwd!r}")
    print_info(f"原始字节: {raw!r}")
    print_success(f"标准 Base64: {std}")
    print_info(f"URL-safe Base64: {safe}")

    sample = f"""\
明文: {pwd!r}
原始字节: {raw!r}
标准 Base64: {std}
URL-safe Base64: {safe}
"""
    set_sample(2, sample)


def collect_section():
    from utils.markdown import StepSection
    from context import get_sample

    pwd = get_password()
    sample = get_sample(2, f"明文: {pwd!r}\n标准 Base64: <待生成>\nURL-safe Base64: <待生成>")
    return StepSection(2, "Base64 编码", LECTURE_BASE64, B64_SAMPLE_CODE, sample)