"""Hash 加密原理与实战教学项目 — CLI 入口。"""

from __future__ import annotations

import sys
from pathlib import Path

from context import set_password, get_password, reset_samples
from utils.formatting import print_warning, print_error, print_success, prompt_continue
from utils.markdown import generate_guide
from steps import (
    step1_demo,
    step2_demo,
    step3_demo,
    step4_demo,
    step5_demo,
    step6_demo,
    step1_sha256,
    step2_base64,
    step3_salt,
    step4_kdf,
    step5_checksum,
    step6_rainbow,
)

MENU = """\
  1. SHA-256 基础哈希
  2. Base64 编码
  3. 盐值机制
  4. 密钥派生 (PBKDF2-HMAC-SHA256)
  5. 文件校验和生成/验证
  6. 彩虹表攻击演示
  a. 全部运行
  q. 退出
"""

STEPS = [
    ("1", "SHA-256 基础哈希", step1_demo, step1_sha256.collect_section),
    ("2", "Base64 编码", step2_demo, step2_base64.collect_section),
    ("3", "盐值机制", step3_demo, step3_salt.collect_section),
    ("4", "密钥派生 (PBKDF2-HMAC-SHA256)", step4_demo, step4_kdf.collect_section),
    ("5", "文件校验和生成/验证", step5_demo, step5_checksum.collect_section),
    ("6", "彩虹表攻击演示", step6_demo, step6_rainbow.collect_section),
]


def ask_password() -> str:
    while True:
        try:
            pwd = input("请输入要演示的密码: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if pwd:
            return pwd
        print_warning("密码不能为空，请重新输入。")


def print_menu() -> None:
    pwd = get_password()
    print(f"\n当前密码: {pwd!r}\n")
    print(MENU)


def run_all() -> None:
    reset_samples()
    sections = []
    for _, title, demo_fn, collect_fn in STEPS:
        demo_fn()
        sections.append(collect_fn())

    try:
        path = generate_guide(sections, output_path=Path(__file__).resolve().parent / "HASH_DEMO_GUIDE.md")
        print(f"\n文档已生成: {path}")
    except Exception as exc:
        print_error(f"文档生成失败: {exc}")


def main() -> None:
    pwd = ask_password()
    set_password(pwd)
    print_success(f"已设置演示密码: {pwd!r}")

    while True:
        print_menu()
        try:
            choice = input("请选择 (1-6/a/q): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "q":
            print("再见！")
            break
        elif choice == "a":
            run_all()
            prompt_continue()
            break
        elif choice in ("1", "2", "3", "4", "5", "6"):
            for key, _, demo_fn, _ in STEPS:
                if key == choice:
                    demo_fn()
                    prompt_continue()
                    break
        else:
            print_warning("无效输入，请重新选择。")


if __name__ == "__main__":
    main()