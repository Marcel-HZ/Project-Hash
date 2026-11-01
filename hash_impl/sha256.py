"""SHA-256 hash implementation (pure Python, FIPS 180-4)."""

from __future__ import annotations

from hash_impl.constants import H0_INIT, K
from hash_impl.padding import pad, split_blocks
from hash_impl.utils import bytes_to_int, gamma0, gamma1, int_to_bytes, maj, rotr, sigma0, sigma1


class SHA256:
    """SHA-256 hash with teaching trace interface."""

    def __init__(self) -> None:
        self._h = list(H0_INIT)
        self._buffer = bytearray()
        self._total_len = 0
        self._trace: dict = {}

    def update(self, data: bytes) -> None:
        self._buffer.extend(data)
        self._total_len += len(data)
        # Process complete 64-byte blocks
        while len(self._buffer) >= 64:
            block = bytes(self._buffer[:64])
            del self._buffer[:64]
            self._process_block(block)

    def _process_block(self, block: bytes) -> None:
        # Message schedule W[0..63]
        w = [0] * 64
        for i in range(16):
            w[i] = bytes_to_int(block[i * 4:(i + 1) * 4])
        for i in range(16, 64):
            w[i] = (gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF

        # Working variables
        a, b, c, d, e, f, g, h = self._h

        # 64 rounds
        for t in range(64):
            t1 = (h + sigma1(e) + ((e & f) ^ (~e & g)) + K[t] + w[t]) & 0xFFFFFFFF
            t2 = (sigma0(a) + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        # Update hash state
        self._h[0] = (self._h[0] + a) & 0xFFFFFFFF
        self._h[1] = (self._h[1] + b) & 0xFFFFFFFF
        self._h[2] = (self._h[2] + c) & 0xFFFFFFFF
        self._h[3] = (self._h[3] + d) & 0xFFFFFFFF
        self._h[4] = (self._h[4] + e) & 0xFFFFFFFF
        self._h[5] = (self._h[5] + f) & 0xFFFFFFFF
        self._h[6] = (self._h[6] + g) & 0xFFFFFFFF
        self._h[7] = (self._h[7] + h) & 0xFFFFFFFF

    def digest(self) -> bytes:
        # Save state
        saved_h = list(self._h)
        saved_buffer = bytes(self._buffer)
        saved_total = self._total_len

        # Finalize: pad remaining buffer
        data = bytes(self._buffer)
        padded = pad(data, self._total_len)
        for block in split_blocks(padded):
            self._process_block(block)

        result = b"".join(int_to_bytes(h, 4) for h in self._h)

        # Restore state (allow re-digest)
        self._h = saved_h
        self._buffer = bytearray(saved_buffer)
        self._total_len = saved_total
        return result

    def hexdigest(self) -> str:
        return self.digest().hex()

    def get_trace(self, data: bytes = None) -> dict:
        """Return full computation trace for teaching.

        If data is provided, compute trace for that data.
        Otherwise use accumulated buffer + processed data.
        """
        if data is not None:
            msg = data
        else:
            msg = bytes(self._buffer)

        padded = pad(msg)
        blocks = split_blocks(padded)

        # Compute message schedule and round states for first block only (teaching)
        trace: dict = {
            "original_message": msg,
            "original_len": len(msg),
            "padded_message": padded,
            "padded_len": len(padded),
            "num_blocks": len(blocks),
            "blocks": blocks,
            "initial_h": list(H0_INIT),
            "block_traces": [],
        }

        h = list(H0_INIT)
        for bi, block in enumerate(blocks):
            w = [0] * 64
            for i in range(16):
                w[i] = bytes_to_int(block[i * 4:(i + 1) * 4])
            for i in range(16, 64):
                w[i] = (gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF

            initial_h = list(h)
            a, b, c, d, e, f, g, hh = h
            round_states = []

            for t in range(64):
                ch_val = (e & f) ^ (~e & g)
                maj_val = (a & b) ^ (a & c) ^ (b & c)
                t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ch_val + K[t] + w[t]) & 0xFFFFFFFF
                t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + maj_val) & 0xFFFFFFFF
                round_states.append({
                    "round": t,
                    "a": a, "b": b, "c": c, "d": d,
                    "e": e, "f": f, "g": g, "h": hh,
                    "w": w[t], "k": K[t],
                })
                hh = g
                g = f
                f = e
                e = (d + t1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (t1 + t2) & 0xFFFFFFFF

            # Update hash
            h[0] = (h[0] + a) & 0xFFFFFFFF
            h[1] = (h[1] + b) & 0xFFFFFFFF
            h[2] = (h[2] + c) & 0xFFFFFFFF
            h[3] = (h[3] + d) & 0xFFFFFFFF
            h[4] = (h[4] + e) & 0xFFFFFFFF
            h[5] = (h[5] + f) & 0xFFFFFFFF
            h[6] = (h[6] + g) & 0xFFFFFFFF
            h[7] = (h[7] + hh) & 0xFFFFFFFF

            block_trace = {
                "block_index": bi,
                "initial_h": initial_h,
                "message_schedule": w,
                "round_states": round_states,
                "result_h": list(h),
            }
            trace["block_traces"].append(block_trace)

        trace["final_digest"] = b"".join(int_to_bytes(hv, 4) for hv in h)
        return trace


def sha256(data: bytes) -> bytes:
    """Convenience function: compute SHA-256 digest."""
    s = SHA256()
    s.update(data)
    return s.digest()


def sha256_hex(data: bytes) -> str:
    """Convenience function: compute SHA-256 hex digest."""
    return sha256(data).hex()