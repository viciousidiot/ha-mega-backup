"""Tests for MEGA's file fingerprint (the ``c`` node attribute)."""

from __future__ import annotations

import pytest
from fake_mega import reference_fingerprint_crc

from custom_components.mega_backup import client as mega


def _chunks(data: bytes, chunk_size: int) -> list[bytes]:
    """Split data into fixed size blocks, the way the upload stream does."""
    if not data:
        return []
    return [
        data[offset : offset + chunk_size] for offset in range(0, len(data), chunk_size)
    ]


def _serialize64(value: int) -> bytes:
    """Straightforward implementation of MEGA's Serialize64."""
    raw = bytearray(9)
    length = 0
    while value:
        length += 1
        raw[length] = value & 0xFF
        value >>= 8
    raw[0] = length
    return bytes(raw[: length + 1])


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, b"\x00"),
        (1, b"\x01\x01"),
        (0x0102, b"\x02\x02\x01"),
        (0xFFFFFFFF, b"\x04\xff\xff\xff\xff"),
        (1_700_000_000, b"\x04\x00\xf1\x53\x65"),
    ],
)
def test_serialize64(value: int, expected: bytes) -> None:
    """Serialized modification times match MEGA's encoding."""
    assert mega._serialize64(value) == expected


def test_tiny_file_fingerprint_is_verbatim() -> None:
    """For files of at most 16 bytes the bytes themselves form the CRC."""
    fingerprint = mega._FileFingerprint(4)
    fingerprint.update(b"\x03\x04\x05\x06")
    raw = mega.b64url_decode(fingerprint.digest(1))
    assert raw[:16] == b"\x03\x04\x05\x06" + bytes(12)
    assert raw[16:] == b"\x01\x01"


@pytest.mark.parametrize(
    ("size", "chunk_size"),
    [
        (0, 1),
        (1, 1),
        (16, 3),
        (17, 17),
        (100, 7),
        (8191, 1024),
        (8192, 8192),
        (8193, 8192),
        (20_000, 4096),
        (200_000, 65_536),
        (1_500_000, 131_072),
    ],
)
def test_streamed_fingerprint_matches_reference(size: int, chunk_size: int) -> None:
    """Streaming the data in arbitrary blocks yields the reference fingerprint."""
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    fingerprint = mega._FileFingerprint(size)
    for chunk in _chunks(data, chunk_size):
        fingerprint.update(chunk)

    raw = mega.b64url_decode(fingerprint.digest(1_700_000_000))
    assert raw[:16] == reference_fingerprint_crc(data)
    assert raw[16:] == _serialize64(1_700_000_000)


@pytest.mark.parametrize("size", [100, 8193, 200_000])
def test_fingerprint_detects_a_missing_tail(size: int) -> None:
    """A stream that ends early cannot produce a fingerprint."""
    fingerprint = mega._FileFingerprint(size)
    fingerprint.update(bytes(size - 1))
    with pytest.raises(mega.MegaSizeMismatch):
        fingerprint.digest(0)


def test_fingerprint_is_url_safe_base64() -> None:
    """The attribute uses MEGA's unpadded URL safe base64 alphabet."""
    fingerprint = mega._FileFingerprint(20_000)
    fingerprint.update(bytes(range(256)) * 78 + bytes(range(32)))
    encoded = fingerprint.digest(1)
    assert "=" not in encoded
    assert "+" not in encoded
    assert "/" not in encoded
