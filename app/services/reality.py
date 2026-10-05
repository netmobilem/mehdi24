"""TiTaN Panel — REALITY / Shadowsocks crypto helpers.

REALITY needs an X25519 key pair in Xray's own encoding (base64url, no padding).
Doing it panel-side means a new inbound is *complete* the moment it is created —
no round-trip to the node just to learn its public key.
"""

from __future__ import annotations

import base64
import os
import secrets
import string

# ── x25519 ───────────────────────────────────────────────────────────────────
try:  # pragma: no cover - depends on the deployment image
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def generate_reality_keypair() -> tuple[str, str]:
    """Return ``(private_key, public_key)`` in Xray/base64url form."""
    if HAVE_CRYPTO:
        private = X25519PrivateKey.generate()
        private_raw = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return _b64(private_raw), _b64(public_raw)

    # deterministic fallback: 32 random bytes as the private scalar
    private_raw = os.urandom(32)
    return _b64(private_raw), _b64(_x25519_base(private_raw))


def public_from_private(private_b64: str) -> str:
    if HAVE_CRYPTO:
        private = X25519PrivateKey.from_private_bytes(_unb64(private_b64))
        raw = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return _b64(raw)
    return _b64(_x25519_base(_unb64(private_b64)))


def _x25519_base(scalar: bytes) -> bytes:
    """Minimal RFC 7748 X25519 implementation (used only if cryptography is absent)."""
    P = 2**255 - 19

    def clamp(value: int) -> int:
        value &= ~7
        value &= ~(128 << 8 * 31) if False else value
        value |= 1 << 254
        value &= ~(1 << 255)
        return value

    k = clamp(int.from_bytes(scalar, "little"))
    x1 = 9
    x2, z2, x3, z3 = 1, 0, 9, 1
    swap = 0
    for bit in reversed(range(255)):
        kt = (k >> bit) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


# ── shadowsocks 2022 helpers ─────────────────────────────────────────────────
def generate_ss_password(cipher: str = "2022-blake3-aes-128-gcm") -> str:
    """Shadowsocks 2022 wants a base64 key whose length matches the cipher."""
    size = 32 if "256" in cipher else 16
    return base64.b64encode(os.urandom(size)).decode()


def generate_short_id(length: int = 8) -> str:
    alphabet = string.hexdigits.lower()[:16]
    return "".join(secrets.choice(alphabet) for _ in range(length))


def random_path(prefix: str = "/titan") -> str:
    return f"{prefix}/{secrets.token_hex(4)}"


def random_service_name() -> str:
    return f"titan-{secrets.token_hex(3)}"
