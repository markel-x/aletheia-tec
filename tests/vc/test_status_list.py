"""Codificación de Token Status List."""

from __future__ import annotations

import zlib

import pytest

from aletheia.vc.encoding import b64url_encode
from aletheia.vc.status_list import StatusList, StatusListError, StatusReference


@pytest.mark.parametrize("bits", [1, 2, 4, 8])
def test_set_get_roundtrip(bits: int) -> None:
    sl = StatusList(size=64, bits=bits)
    max_value = (1 << bits) - 1
    for idx in range(64):
        sl.set(idx, idx % (max_value + 1))
    decoded = StatusList.decode(sl.encode())
    assert [decoded.get(i) for i in range(64)] == [i % (max_value + 1) for i in range(64)]


def test_default_list_size_is_compact() -> None:
    sl = StatusList(size=131_072)
    sl.set(48_213, 1)
    encoded = sl.encode()
    assert len(encoded["lst"]) < 200  # 16 KiB casi vacíos se comprimen muy bien
    assert StatusList.decode(encoded).get(48_213) == 1


def test_decompression_bomb_is_rejected() -> None:
    bomb = b64url_encode(zlib.compress(b"\x00" * (4 << 20)))
    with pytest.raises(StatusListError):
        StatusList.decode({"bits": 1, "lst": bomb})


@pytest.mark.parametrize(
    "obj", [None, {}, {"bits": 3, "lst": "eNrbuRgAAhcBXQ"}, {"bits": 1, "lst": "no-es-zlib"}]
)
def test_invalid_status_list_objects(obj: object) -> None:
    with pytest.raises(StatusListError):
        StatusList.decode(obj)


def test_out_of_range_index() -> None:
    with pytest.raises(StatusListError):
        StatusList(size=8).get(8)


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"status": {"status_list": {"idx": -1, "uri": "https://x"}}},
        {"status": {"status_list": {"idx": True, "uri": "https://x"}}},
        {"status": {"status_list": {"idx": 1, "uri": "http://x"}}},
    ],
)
def test_status_reference_validation(claims: dict[str, object]) -> None:
    with pytest.raises(StatusListError):
        StatusReference.from_claims(claims)


def test_trailing_bytes_after_zlib_stream_are_rejected() -> None:
    lst = b64url_encode(zlib.compress(b"\x00" * 4) + b"garbage")
    with pytest.raises(StatusListError):
        StatusList.decode({"bits": 1, "lst": lst})
