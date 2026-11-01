"""Helper functions for SHA-256: rotation, logical functions, mod 2^32 addition."""

from __future__ import annotations

MASK32 = 0xFFFFFFFF


def rotr(x: int, n: int) -> int:
    """Rotate right x by n bits (32-bit)."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def ch(x: int, y: int, z: int) -> int:
    """Ch(x,y,z) = (x AND y) XOR (NOT x AND z)."""
    return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
    """Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)."""
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x: int) -> int:
    """Σ0(x) = ROTR(x,2) XOR ROTR(x,13) XOR ROTR(x,22)."""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def sigma1(x: int) -> int:
    """Σ1(x) = ROTR(x,6) XOR ROTR(x,11) XOR ROTR(x,25)."""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def gamma0(x: int) -> int:
    """σ0(x) = ROTR(x,7) XOR ROTR(x,18) XOR (x >> 3)."""
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def gamma1(x: int) -> int:
    """σ1(x) = ROTR(x,17) XOR ROTR(x,19) XOR (x >> 10)."""
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def add32(*vals: int) -> int:
    """Mod 2^32 addition of multiple values."""
    return sum(vals) & MASK32


def int_to_bytes(x: int, length: int) -> bytes:
    """Convert integer to big-endian bytes."""
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(b, "big")