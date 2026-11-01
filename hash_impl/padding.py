"""SHA-256 message padding."""

from __future__ import annotations

from hash_impl.utils import int_to_bytes


def pad(message: bytes, total_len: int = None) -> bytes:
    """Apply SHA-256 padding to message.

    If total_len is given, use it for the final length field (for incremental use).
    """
    if total_len is None:
        total_len = len(message)
    original_len = total_len
    padded = message + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += int_to_bytes(original_len * 8, 8)
    return padded


def split_blocks(padded: bytes) -> list[bytes]:
    """Split padded message into 64-byte blocks."""
    return [padded[i:i + 64] for i in range(0, len(padded), 64)]