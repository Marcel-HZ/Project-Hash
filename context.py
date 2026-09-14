"""全局上下文：存储用户输入的密码、各步骤运行时样本数据。"""

from __future__ import annotations

PASSWORD: str = ""
SAMPLES: dict[int, str] = {}  # step_number -> real sample output


def set_password(pwd: str) -> None:
    """设置当前演示使用的密码。"""
    global PASSWORD
    PASSWORD = pwd


def get_password() -> str:
    """获取当前演示使用的密码。"""
    return PASSWORD


def set_sample(step: int, text: str) -> None:
    """记录指定步骤的运行时样本输出。"""
    SAMPLES[step] = text


def get_sample(step: int, fallback: str = "") -> str:
    """获取指定步骤的运行时样本输出，无则返回 fallback。"""
    return SAMPLES.get(step, fallback)


def reset_samples() -> None:
    """清空所有样本（每次全跑前调用）。"""
    global SAMPLES
    SAMPLES = {}