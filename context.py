"""全局上下文：存储用户输入的密码、各步骤运行时样本数据。"""

from __future__ import annotations

PASSWORD: str = ""
SAMPLES: dict[int, str] = {}

# SHA-256 visualization state
SHA256_TRACE: dict = {}
SHA256_DIGEST: str = ""
SHA256_CURRENT_STAGE: int = 0
SHA256_CURRENT_BLOCK: int = 0
SHA256_CURRENT_ROUND: int = 0
SHA256_VISUALIZATION_MODE: str = "interactive"


def set_password(pwd: str) -> None:
    global PASSWORD
    PASSWORD = pwd


def get_password() -> str:
    return PASSWORD


def set_sample(step: int, text: str) -> None:
    SAMPLES[step] = text


def get_sample(step: int, fallback: str = "") -> str:
    return SAMPLES.get(step, fallback)


def reset_samples() -> None:
    global SAMPLES
    SAMPLES = {}


def set_trace(trace: dict) -> None:
    global SHA256_TRACE
    SHA256_TRACE = trace


def get_trace() -> dict:
    return SHA256_TRACE


def reset_trace() -> None:
    global SHA256_TRACE, SHA256_DIGEST, SHA256_CURRENT_STAGE, SHA256_CURRENT_BLOCK, SHA256_CURRENT_ROUND
    SHA256_TRACE = {}
    SHA256_DIGEST = ""
    SHA256_CURRENT_STAGE = 0
    SHA256_CURRENT_BLOCK = 0
    SHA256_CURRENT_ROUND = 0