"""Interoperability with an independent MEGA implementation.

The expected values in this module were produced by ``megajs`` 1.3.10, a
third-party MEGA client, for a fixed 24 byte upload key. They pin the exact
key layout MEGA clients require: the stored node key is folded before it is
used, and the folded key decrypts both the contents and the attributes.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from custom_components.mega_backup import client as mega

KEY = mega.b64url_decode("CzBVep_E6Q4zWH2ix-wRNluApcrvFDle")
AES_KEY = KEY[:16]
NONCE = KEY[16:24]

# size, ciphertext sha256, merged node key, meta MAC (all from megajs).
VECTORS: list[tuple[int, str, str, str]] = [
    (
        1,
        "8a331fdde7032f33a71e1b2e257d80166e348e00fcb17914f48bdb57a1c63007",
        "ULDwsHDQ0FBrYgjS2ixdf1uApcrvFDleWDp1cB3ATEk",
        "WDp1cB3ATEk",
    ),
    (
        16,
        "67d5f77144b75c1c13dad9e7b6f803e39c6e57fd0b83fbb87c4fc45b6bbd8533",
        "ULDwsHDQ0FAuk0yfMDe6SluApcrvFDleHcsxPffbq3w",
        "HcsxPffbq3w",
    ),
    (
        128 * 1024,
        "4723d381fab20d9397cf011427a9a17bab5ff9a70b7d0bdef9ab3d1884072a8a",
        "ULDwsHDQ0FAQ5e1aN5XzzFuApcrvFDleI72Q-PB54vo",
        "I72Q-PB54vo",
    ),
    (
        300 * 1024,
        "9fdfeb153d321dc79a301c2bc1a9db0d8eb79e222a33cd9a3a0cd9d14ae4512b",
        "ULDwsHDQ0FDj7Bd3WJUbgVuApcrvFDle0LRq1Z95Crc",
        "0LRq1Z95Crc",
    ),
    (
        1024 * 1024 + 128 * 1024,
        "541ffa3d55358884e04da495661551c4bdc3d20d77e5cfab422a3832dea4e9b0",
        "ULDwsHDQ0FAZN5q7-rg4oluApcrvFDleKm_nGT1UKZQ",
        "Km_nGT1UKZQ",
    ),
]


def _plaintext(size: int) -> bytes:
    """Return the deterministic test payload megajs encrypted (xorshift32)."""
    data = bytearray(size)
    state = 0xA5A5A5A5
    for index in range(size):
        state ^= (state << 13) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        state ^= state >> 17
        state &= 0xFFFFFFFF
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        data[index] = state & 0xFF
    return bytes(data)


def _ciphertext(data: bytes) -> bytes:
    encryptor = Cipher(
        algorithms.AES(AES_KEY), modes.CTR(mega._ctr_iv(NONCE))
    ).encryptor()
    return encryptor.update(data) + encryptor.finalize()


@pytest.mark.parametrize(("size", "cipher_sha", "merged", "mac"), VECTORS)
def test_upload_crypto_matches_megajs(
    size: int, cipher_sha: str, merged: str, mac: str
) -> None:
    """Our MAC, key merging and ciphertext match an independent client."""
    data = _plaintext(size)

    state = mega._MegaMac(AES_KEY, NONCE)
    state.update(data)
    meta_mac = state.digest()
    assert mega.b64url_encode(meta_mac) == mac

    node_key = mega._merge_key_mac(KEY, meta_mac)
    assert mega.b64url_encode(node_key) == merged
    assert hashlib.sha256(_ciphertext(data)).hexdigest() == cipher_sha


@pytest.mark.parametrize(("size", "cipher_sha", "merged", "mac"), VECTORS)
def test_megajs_can_decrypt_our_upload(
    size: int, cipher_sha: str, merged: str, mac: str
) -> None:
    """Replay a megajs download: fold the key, decrypt, verify the MAC."""
    del cipher_sha
    data = _plaintext(size)
    node_key: Any = mega.b64url_decode(merged)
    assert mega.b64url_encode(node_key[24:32]) == mac

    aes_key = mega._node_cipher_key(node_key)
    assert aes_key == AES_KEY

    decryptor = Cipher(
        algorithms.AES(aes_key), modes.CTR(mega._ctr_iv(node_key[16:24]))
    ).decryptor()
    plain = decryptor.update(_ciphertext(data)) + decryptor.finalize()
    assert plain == data

    state = mega._MegaMac(aes_key, node_key[16:24])
    state.update(plain)
    assert state.digest() == node_key[24:32]


def test_attributes_use_the_same_folded_key_as_the_contents() -> None:
    """The node key must fold to the key that encrypts the attributes."""
    state = mega._MegaMac(AES_KEY, NONCE)
    state.update(b"contents")
    node_key = mega._merge_key_mac(KEY, state.digest())

    attributes = mega.encrypt_attributes(
        {"n": "backup.tar", "c": "fingerprint"}, mega._node_cipher_key(node_key)
    )
    assert mega.decrypt_attributes(attributes, node_key) == {
        "n": "backup.tar",
        "c": "fingerprint",
    }
