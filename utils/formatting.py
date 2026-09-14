"""统一的控制台输出工具。"""

from __future__ import annotations

import sys
from typing import Iterable, Iterator, TypeVar

T = TypeVar("T")


def print_step_header(n: int, title: str) -> None:
    print(f"\n=== Step {n}: {title} ===")


def print_success(msg: str) -> None:
    print(f"  [OK] {msg}")


def print_info(msg: str) -> None:
    print(f"  {msg}")


def print_warning(msg: str) -> None:
    print(f"  [!] {msg}")


def print_error(msg: str) -> None:
    print(f"  [X] {msg}")


def print_code_block(code: str, title: str | None = None) -> None:
    if title:
        print(f"  {title}")
    print("  ```python")
    for line in code.splitlines():
        print(f"  {line}")
    print("  ```")


def prompt_continue(prompt: str = "按回车继续...") -> None:
    try:
        input(f"\n{prompt}")
    except (EOFError, KeyboardInterrupt):
        print()


def make_progress_bar(iterable: Iterable[T], desc: str = "", total: int | None = None) -> Iterator[T]:
    items = list(iterable) if not hasattr(iterable, "__len__") else iterable
    if total is None and hasattr(items, "__len__"):
        total = len(items)
    try:
        from tqdm import tqdm
        return tqdm(items, desc=desc, total=total, unit="B", unit_scale=True)
    except ImportError:
        for i, item in enumerate(items, 1):
            if total and i % max(1, total // 20) == 0:
                pct = i / total * 100
                print(f"\r  {desc} {pct:.0f}%", end="", flush=True)
            yield item
        if total:
            print(f"\r  {desc} 100%")
        return