"""Step 5: 文件校验和生成/验证。"""

from __future__ import annotations

from hash_impl.sha256 import SHA256
import os
import tempfile
import time
from pathlib import Path

from context import get_password, set_sample
from utils.formatting import (
    print_step_header,
    print_success,
    print_info,
    print_warning,
    print_error,
    prompt_continue,
)

LECTURE_CHECKSUM = """\
文件校验和用于验证数据完整性，常见于下载校验、软件分发、版本比对。

流式计算原理：
  1. 将文件切分为固定大小的块（如 8KB），逐块送入哈希更新器。
  2. 哈希对象内部维护状态，无需一次性加载整个文件到内存。
  3. 对 GB 级大文件，内存占用恒定为 O(1)，避免 OOM。
  4. 进度条实时反馈处理进度。

验证流程：
  expected = "e3b0c44..."  # 来源方提供的正确哈希
  actual = file_sha256(path)
  if actual == expected:  -> 验证通过
  else:                   -> 验证失败（数据被篡改/传输错误）

本演示会创建一个临时文件，计算其 SHA-256，然后篡改一字节并重新验证。
"""

CHECKSUM_SAMPLE_CODE = '''\
def file_sha256(path: Path, chunk_size: int = 8192) -> str:
    h = SHA256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: Path, expected: str) -> bool:
    return file_sha256(path) == expected
'''


def file_sha256(path: Path, chunk_size: int = 8192) -> str:
    """流式计算文件 SHA-256（不显示进度条）"""
    h = SHA256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: Path, expected: str) -> bool:
    return file_sha256(path) == expected


def demo() -> None:
    print_step_header(5, "文件校验和生成/验证")

    pwd = get_password()
    print_info(f"明文: {pwd!r}")

    tmpdir = Path(tempfile.mkdtemp())
    test_file = tmpdir / "password_data.bin"
    content = (pwd * 200).encode("utf-8")
    test_file.write_bytes(content)
    print_info(f"测试文件: password_data.bin ({len(content):,} bytes)")

    start = time.perf_counter()
    original_hash = file_sha256(test_file)
    elapsed = time.perf_counter() - start
    print_success(f"原始 SHA-256: {original_hash}")
    print_info(f"用时: {elapsed:.4f}s")

    ok = verify_file(test_file, original_hash)
    print_success(f"验证原始文件: {'通过' if ok else '失败'}")

    # 篡改文件
    with open(test_file, "r+b") as f:
        f.seek(512)
        f.write(b"\x00")
    print_warning("已篡改文件偏移 512 处一字节...")

    start2 = time.perf_counter()
    new_hash = file_sha256(test_file)
    elapsed2 = time.perf_counter() - start2
    print_info(f"篡改后 SHA-256: {new_hash}")
    print_info(f"用时: {elapsed2:.4f}s")

    ok2 = verify_file(test_file, original_hash)
    if not ok2:
        print_error("验证失败！数据完整性已被破坏。")
    else:
        print_error("验证仍然通过（异常情况）")

    sample = f"""\
明文: {pwd!r}
测试文件: password_data.bin ({len(content):,} bytes)
原始 SHA-256: {original_hash}
用时: {elapsed:.4f}s
验证原始文件: 通过
已篡改文件偏移 512 处一字节...
篡改后 SHA-256: {new_hash}
用时: {elapsed2:.4f}s
验证失败！数据完整性已被破坏。
"""
    set_sample(5, sample)
    prompt_continue("查看下一个步骤...")


def collect_section():
    from utils.markdown import StepSection
    from context import get_sample

    pwd = get_password()
    sample = get_sample(5, f"明文: {pwd!r}\n<等待运行生成真实样本>")
    return StepSection(5, "文件校验和生成/验证", LECTURE_CHECKSUM, CHECKSUM_SAMPLE_CODE, sample)