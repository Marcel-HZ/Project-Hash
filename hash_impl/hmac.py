"""HMAC-SHA256 based on autonomous SHA256."""

from __future__ import annotations

from hash_impl.sha256 import SHA256


def _digest(data: bytes) -> bytes:
    s = SHA256()
    s.update(data)
    return s.digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    block_size = 64
    if len(key) > block_size:
        key = _digest(key)
    key = key.ljust(block_size, b"\x00")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    inner_hash = _digest(ipad + message)
    return _digest(opad + inner_hash)